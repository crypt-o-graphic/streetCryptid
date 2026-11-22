//! Which friends are worth a dial: the data budget's one choke point.
//!
//! ## The hole this fills
//! On 2026-11-21 a Pixel 10 with 14 friends had sent 34 GB over mobile data in a week. `net.conns`
//! (`conn_ledger`) showed that completed connections moved about 590 MB a day. The other 6.5 GB a
//! day went on dials that never completed a handshake. Every push dialled every friend, and every
//! pull dialled every friend once PER NAMESPACE (18 namespaces), about 2,100 dials an hour.
//! Most of those friends were iPhones suspended in a pocket. Each unanswered dial cost about
//! 145 KB of QUIC Initials and hole-punch probes sprayed at stale addresses until the handshake
//! timed out.
//!
//! Eight days of fleet telemetry (38,163 push dials, 2026-11-14..22) say how predictable that
//! was. P(a friend answers a push) by the time since the last exchange with it:
//!
//! | since last exchange | share of dials | answered |
//! | ------------------- | -------------- | -------- |
//! | < 1 min             | 6 %            | 89 %     |
//! | < 5 min             | 8 %            | 62 %     |
//! | < 15 min            | 5 %            | 18 %     |
//! | < 1 h               | 12 %           | 7 %      |
//! | older, or never     | 70 %           | < 2 %    |
//!
//! Gating on "an exchange in the last 15 min, or a fresh publish from them" kept 98 % of the
//! direct deliveries with 24 % of the dials. Everything a friend publishes reaches the stash
//! anyway (it answers 94 % of pushes), so a dial to a sleeping friend buys nothing.
//!
//! ## How
//! [`DialGateHook`] is installed FIRST on the node's endpoint, so it sees every dial whoever makes
//! it: our push and pull, but also the dials iroh-docs makes on its own (it re-dials every peer a
//! namespace "usefully synced with" on every `start_sync`, and every gossip neighbour's sync
//! report), the blob downloader's, and gossip's. It refuses a dial before a packet is sent, so a
//! refusal costs nothing. Callers that can tell in advance ([`allow_friend`]) leave cold friends
//! out, which keeps their spans honest.
//!
//! What counts as evidence that a friend is awake, by [`DataMode`]:
//! - **inbound**: it opened a connection to us recently. Our OWN dials deliberately do not count.
//!   Otherwise two always-on Androids would keep each other warm for ever by pushing to each other
//!   every five minutes, which was 2 × 288 × 20 KB a day for one pair.
//! - **fresh**: an entry it wrote reached us (from anyone, the stash included) while still
//!   recent. It was awake at that moment, and the next pull or push dials it.
//! - **local**: we last spoke to it over BLE or a LAN address. That costs no mobile data and is
//!   the offline mesh's only path, so it is allowed in every mode.
//!
//! Dials to one friend are COALESCED: the first goes out, and the rest (one per namespace) wait
//! for its handshake and then go out, or are refused if it fails. A friend whose dial failed
//! cools down before the next attempt.
//!
//! Gossip is off outside [`DataMode::Realtime`]. On the Pixel it cost ~340 MB a day: HyParView
//! upkeep and PlumTree re-broadcasts over 18 topics, mostly to the one other always-on phone.
//! Pushes to awake friends and pulls from the stash already carry everything it delivered.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use iroh::endpoint::{
    AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks, Side,
};
use iroh::{EndpointAddr, TransportAddr};

/// How much mobile data the node may spend reaching friends' phones directly. The stash and the
/// repeaters are always reachable and always allowed; this decides the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum DataMode {
    /// Never dial a friend's phone over the internet. The stash and repeaters carry everything;
    /// a friend reaches us when it dials us, and nearby friends (BLE / same Wi-Fi) still sync.
    /// Background pulls stop; opening the app pulls.
    Saver,
    /// Dial a friend only on evidence that it is awake (see the module docs). The default.
    Balanced,
    /// Dial every friend as before, with gossip, but coalesced and cooled down after a failure.
    Realtime,
}

impl DataMode {
    pub fn as_str(self) -> &'static str {
        match self {
            DataMode::Saver => "saver",
            DataMode::Balanced => "balanced",
            DataMode::Realtime => "realtime",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "saver" => Some(DataMode::Saver),
            "balanced" => Some(DataMode::Balanced),
            "realtime" => Some(DataMode::Realtime),
            _ => None,
        }
    }

    /// The shortest gap between two background pulls (`pull_latest`). `None`: no background
    /// pulls at all. A pull costs about 350 KB (18 namespaces from the stash, about 19 KB each),
    /// so the 5 to 15 min the platforms ask for came to 33 to 100 MB a day, the whole budget on
    /// its own, to refresh dots nobody was looking at. Opening the app pulls at once anyway.
    pub fn background_pull_floor(self) -> Option<Duration> {
        match self {
            DataMode::Saver => None,
            DataMode::Balanced => Some(Duration::from_secs(60 * 60)),
            DataMode::Realtime => Some(Duration::ZERO),
        }
    }
}

/// Evidence older than this is no longer evidence. The answer rate falls from 62 % to 18 %
/// between 5 and 15 minutes after the last exchange.
const INBOUND_WARM: Duration = Duration::from_secs(5 * 60);
/// An entry stamped this recently means its author was awake then.
const FRESH_WARM: Duration = Duration::from_secs(5 * 60);
/// A BLE / LAN contact this recent means the friend is still close by.
const LOCAL_WARM: Duration = Duration::from_secs(15 * 60);
/// In `Balanced`, the least time between two direct exchanges with one friend that is not nearby.
/// Evidence of being awake is itself made by direct exchanges: A's push to B is an inbound
/// connection for B, which makes B push to A, which is an inbound connection for A, and two phones
/// that never sleep would keep each other warm indefinitely, 2 × 288 pushes a day. A friend who is
/// being watched is also polled through the stash every 20 to 90 s, so a quarter of an hour
/// between direct exchanges costs nobody a live dot.
const DIRECT_EVERY: Duration = Duration::from_secs(15 * 60);
/// How long later dials to the same friend wait for the first one's handshake.
const COALESCE_WAIT: Duration = Duration::from_secs(10);

fn cooldown(mode: DataMode) -> Duration {
    match mode {
        DataMode::Realtime => Duration::from_secs(2 * 60),
        _ => Duration::from_secs(10 * 60),
    }
}

/// The ALPNs whose dials to a friend are gated. Pairing and everything else always pass.
const DOCS_ALPN: &[u8] = b"/iroh-sync/1";
const BLOBS_ALPN: &[u8] = b"/iroh-bytes/4";
const GOSSIP_ALPN: &[u8] = b"/iroh-gossip/1";

#[derive(Default)]
struct Peer {
    inbound: Option<Instant>,
    local: Option<Instant>,
    fresh: Option<Instant>,
    cooldown_until: Option<Instant>,
    /// When the last dial to it that was not waiting on another went out.
    last_lead: Option<Instant>,
    /// A dial in flight: when it started, which one it is, and where its outcome is announced.
    inflight: Option<(Instant, u64, tokio::sync::watch::Sender<Option<bool>>)>,
}

struct State {
    mode: DataMode,
    /// Whether a stash or a repeater can carry our fixes to friends, and theirs to us. Without one
    /// a friend's phone is the only path there is, and gating it would leave two friends unable
    /// to exchange anything until one of them happened to dial the other.
    has_carrier: bool,
    friends: HashSet<[u8; 32]>,
    peers: HashMap<[u8; 32], Peer>,
    /// `(reason, alpn)` → refusals since the last [`take_window`].
    refused: BTreeMap<(&'static str, &'static str), u64>,
    coalesced: u64,
    last_background_pull: Option<Instant>,
    next_dial: u64,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let mut guard = STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(guard.get_or_insert_with(|| State {
        mode: DataMode::Balanced,
        has_carrier: false,
        friends: HashSet::new(),
        peers: HashMap::new(),
        refused: BTreeMap::new(),
        coalesced: 0,
        last_background_pull: None,
        next_dial: 0,
    }))
}

pub(crate) fn set_mode(mode: DataMode) {
    with_state(|s| s.mode = mode);
}

pub(crate) fn mode() -> DataMode {
    with_state(|s| s.mode)
}

/// Every friend's endpoint id (recipients and watchers), and whether a stash or repeater is there
/// to carry fixes without them. Called wherever the roles are read.
pub(crate) fn set_friends(friends: impl IntoIterator<Item = [u8; 32]>, has_carrier: bool) {
    let friends: HashSet<[u8; 32]> = friends.into_iter().collect();
    with_state(|s| {
        s.friends = friends;
        s.has_carrier = has_carrier;
    });
}

/// Whether a stash or repeater carries fixes, so the data mode applies at all ([`gating`]).
pub(crate) fn active() -> bool {
    with_state(|s| gating(s.has_carrier))
}

/// Whether the gate decides anything. With no stash and no repeater, friends' phones and the
/// gossip between them are the only way a fix travels, so every dial goes out as it always did:
/// no mode, no coalescing, no cooldown.
fn gating(has_carrier: bool) -> bool {
    has_carrier
}

/// An entry `author` wrote at `entry_ts_us` (microseconds since the epoch, iroh-docs' stamp)
/// reached this replica now.
pub(crate) fn note_fresh(author: [u8; 32], entry_ts_us: u64) {
    let now_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0);
    let age = Duration::from_micros(now_us.saturating_sub(entry_ts_us));
    if age > FRESH_WARM {
        return;
    }
    let seen = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
    with_state(|s| {
        let peer = s.peers.entry(author).or_default();
        if peer.fresh.is_none_or(|t| t < seen) {
            peer.fresh = Some(seen);
        }
    });
}

fn alpn_label(alpn: &[u8]) -> &'static str {
    match alpn {
        DOCS_ALPN => "sync",
        BLOBS_ALPN => "bytes",
        GOSSIP_ALPN => "gossip",
        _ => "other",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Allow,
    Refuse(&'static str),
}

fn recent(t: Option<Instant>, window: Duration, now: Instant) -> bool {
    t.is_some_and(|t| now.saturating_duration_since(t) < window)
}

/// The rule, without the coalescing. Pure over the state so the tests can walk it.
fn verdict(mode: DataMode, peer: Option<&Peer>, alpn: &'static str, now: Instant) -> Verdict {
    let local = peer.is_some_and(|p| recent(p.local, LOCAL_WARM, now));
    if alpn == "gossip" && mode != DataMode::Realtime {
        return Verdict::Refuse("gossip");
    }
    if peer.and_then(|p| p.cooldown_until).is_some_and(|t| now < t) && !local {
        return Verdict::Refuse("cooldown");
    }
    match mode {
        DataMode::Realtime => Verdict::Allow,
        DataMode::Saver if local => Verdict::Allow,
        DataMode::Saver => Verdict::Refuse("saver"),
        DataMode::Balanced => {
            let warm = peer.is_some_and(|p| {
                recent(p.inbound, INBOUND_WARM, now) || recent(p.fresh, FRESH_WARM, now)
            });
            if warm || local {
                Verdict::Allow
            } else {
                Verdict::Refuse("cold")
            }
        }
    }
}

/// Whether a push or pull should include `friend` at all, for the current mode. The hook applies
/// the same rule to every dial anyway; this only keeps cold friends out of the spans.
pub(crate) fn allow_friend(friend: &[u8; 32]) -> bool {
    with_state(|s| {
        if !gating(s.has_carrier) || !s.friends.contains(friend) {
            return true;
        }
        let now = Instant::now();
        let peer = s.peers.get(friend);
        verdict(s.mode, peer, "sync", now) == Verdict::Allow && !rate_limited(s.mode, peer, now)
    })
}

/// Whether a new direct exchange with this friend would come too soon after the last
/// ([`DIRECT_EVERY`]). Nearby friends are never limited: that costs no mobile data.
fn rate_limited(mode: DataMode, peer: Option<&Peer>, now: Instant) -> bool {
    mode == DataMode::Balanced
        && peer.is_some_and(|p| {
            !recent(p.local, LOCAL_WARM, now) && recent(p.last_lead, DIRECT_EVERY, now)
        })
}

/// Whether a background pull may run now, and if so, mark it as run. Foreground pulls (the app on
/// screen) never ask.
pub(crate) fn claim_background_pull() -> bool {
    with_state(|s| {
        // Without a stash or repeater, a background pull is the only way friends' fixes arrive.
        if !gating(s.has_carrier) {
            return true;
        }
        let Some(floor) = s.mode.background_pull_floor() else {
            return false;
        };
        let now = Instant::now();
        if s.last_background_pull
            .is_some_and(|last| now.saturating_duration_since(last) < floor)
        {
            return false;
        }
        s.last_background_pull = Some(now);
        true
    })
}

/// Is `addr` on this network or radio: BLE, or a private / link-local / unique-local IP?
fn is_local(addr: &TransportAddr) -> bool {
    match addr {
        TransportAddr::Custom(_) => true,
        TransportAddr::Ip(ip) => match ip.ip() {
            std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => {
                let first = v6.segments()[0];
                (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
            }
        },
        _ => false,
    }
}

/// The hook. Everything it writes is process-wide.
#[derive(Debug, Clone, Default)]
pub(crate) struct DialGateHook;

impl EndpointHooks for DialGateHook {
    async fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        let label = alpn_label(alpn);
        if label == "other" {
            return BeforeConnectOutcome::Accept;
        }
        let id = *remote_addr.id.as_bytes();
        let now = Instant::now();
        // Decide, and either take the in-flight slot or subscribe to the one already taken, in one
        // critical section.
        enum Next {
            Go,
            Wait(tokio::sync::watch::Receiver<Option<bool>>),
            Lead(u64, tokio::sync::watch::Sender<Option<bool>>),
            No,
        }
        let next = with_state(|s| {
            if !gating(s.has_carrier) {
                return Next::Go;
            }
            let gossip_any = label == "gossip" && s.mode != DataMode::Realtime;
            if !s.friends.contains(&id) && !gossip_any {
                return Next::Go;
            }
            match verdict(s.mode, s.peers.get(&id), label, now) {
                Verdict::Refuse(reason) => {
                    *s.refused.entry((reason, label)).or_default() += 1;
                    Next::No
                }
                Verdict::Allow => {
                    let dial = s.next_dial;
                    let mode = s.mode;
                    let peer = s.peers.entry(id).or_default();
                    match &peer.inflight {
                        Some((started, _, tx))
                            if now.saturating_duration_since(*started) < COALESCE_WAIT =>
                        {
                            let rx = tx.subscribe();
                            s.coalesced += 1;
                            Next::Wait(rx)
                        }
                        _ if rate_limited(mode, Some(&*peer), now) => {
                            *s.refused.entry(("rate", label)).or_default() += 1;
                            Next::No
                        }
                        _ => {
                            let (tx, _rx) = tokio::sync::watch::channel(None);
                            peer.inflight = Some((now, dial, tx.clone()));
                            peer.last_lead = Some(now);
                            s.next_dial += 1;
                            Next::Lead(dial, tx)
                        }
                    }
                }
            }
        });
        match next {
            Next::Go => BeforeConnectOutcome::Accept,
            Next::No => BeforeConnectOutcome::Reject,
            Next::Lead(dial, tx) => {
                // Nobody else may decide this dial failed but the clock: a handshake resolves it as
                // a success from `after_handshake`.
                tokio::spawn(async move {
                    tokio::time::sleep(COALESCE_WAIT).await;
                    if tx.borrow().is_none() {
                        tx.send_replace(Some(false));
                        with_state(|s| {
                            let until = Instant::now() + cooldown(s.mode);
                            let peer = s.peers.entry(id).or_default();
                            if peer.inflight.as_ref().is_some_and(|(_, d, _)| *d == dial) {
                                peer.inflight = None;
                            }
                            peer.cooldown_until = Some(until);
                        });
                    }
                });
                BeforeConnectOutcome::Accept
            }
            Next::Wait(mut rx) => {
                let outcome = tokio::time::timeout(COALESCE_WAIT, async {
                    loop {
                        if let Some(ok) = *rx.borrow_and_update() {
                            return ok;
                        }
                        if rx.changed().await.is_err() {
                            return false;
                        }
                    }
                })
                .await
                .unwrap_or(false);
                if outcome {
                    BeforeConnectOutcome::Accept
                } else {
                    with_state(|s| *s.refused.entry(("coalesced", label)).or_default() += 1);
                    BeforeConnectOutcome::Reject
                }
            }
        }
    }

    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        let id = *conn.remote_id().as_bytes();
        let now = Instant::now();
        let local = conn.paths().iter().any(|path| is_local(path.remote_addr()));
        // A pairing connection is the strongest evidence there is, whichever side opened it.
        let inbound = conn.side() == Side::Server || alpn_label(conn.alpn()) == "other";
        with_state(|s| {
            let peer = s.peers.entry(id).or_default();
            if inbound {
                peer.inbound = Some(now);
            }
            if local {
                peer.local = Some(now);
            }
            peer.cooldown_until = None;
            if let Some((_, _, tx)) = peer.inflight.take() {
                tx.send_replace(Some(true));
            }
        });
        AfterHandshakeOutcome::accept()
    }
}

/// The hook to install, first, on the node's endpoint.
pub(crate) fn hook() -> DialGateHook {
    DialGateHook
}

/// What the gate did since the last call, for `net.conns`.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct Window {
    pub mode: &'static str,
    pub refused: u64,
    /// `reason alpn=n; …`, most first.
    pub refused_by: String,
    pub coalesced: u64,
    /// Friends that would be dialled right now.
    pub warm_friends: u64,
    pub cooling: u64,
}

pub(crate) fn take_window() -> Window {
    with_state(|s| {
        let now = Instant::now();
        let refused = std::mem::take(&mut s.refused);
        let mut rows: Vec<_> = refused.iter().collect();
        rows.sort_by(|a, b| b.1.cmp(a.1));
        let warm = s
            .friends
            .iter()
            .filter(|f| {
                !gating(s.has_carrier)
                    || verdict(s.mode, s.peers.get(*f), "sync", now) == Verdict::Allow
            })
            .count() as u64;
        let cooling = s
            .peers
            .values()
            .filter(|p| p.cooldown_until.is_some_and(|t| now < t))
            .count() as u64;
        Window {
            mode: s.mode.as_str(),
            refused: refused.values().sum(),
            refused_by: rows
                .iter()
                .map(|((reason, alpn), n)| format!("{reason} {alpn}={n}"))
                .collect::<Vec<_>>()
                .join("; "),
            coalesced: std::mem::take(&mut s.coalesced),
            warm_friends: warm,
            cooling,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(now: Instant, ago_s: u64) -> Option<Instant> {
        now.checked_sub(Duration::from_secs(ago_s))
    }

    #[test]
    fn balanced_dials_only_on_evidence() {
        let now = Instant::now() + Duration::from_secs(3600);
        assert_eq!(
            verdict(DataMode::Balanced, None, "sync", now),
            Verdict::Refuse("cold")
        );
        let inbound = Peer {
            inbound: at(now, 60),
            ..Peer::default()
        };
        assert_eq!(
            verdict(DataMode::Balanced, Some(&inbound), "sync", now),
            Verdict::Allow
        );
        let stale = Peer {
            inbound: at(now, 20 * 60),
            ..Peer::default()
        };
        assert_eq!(
            verdict(DataMode::Balanced, Some(&stale), "sync", now),
            Verdict::Refuse("cold")
        );
        let fresh = Peer {
            fresh: at(now, 30),
            ..Peer::default()
        };
        assert_eq!(
            verdict(DataMode::Balanced, Some(&fresh), "bytes", now),
            Verdict::Allow
        );
    }

    #[test]
    fn gossip_is_realtime_only() {
        let now = Instant::now() + Duration::from_secs(3600);
        let warm = Peer {
            inbound: at(now, 10),
            ..Peer::default()
        };
        for mode in [DataMode::Saver, DataMode::Balanced] {
            assert_eq!(
                verdict(mode, Some(&warm), "gossip", now),
                Verdict::Refuse("gossip")
            );
        }
        assert_eq!(
            verdict(DataMode::Realtime, Some(&warm), "gossip", now),
            Verdict::Allow
        );
    }

    #[test]
    fn saver_reaches_only_nearby_friends() {
        let now = Instant::now() + Duration::from_secs(3600);
        let warm = Peer {
            inbound: at(now, 10),
            ..Peer::default()
        };
        assert_eq!(
            verdict(DataMode::Saver, Some(&warm), "sync", now),
            Verdict::Refuse("saver")
        );
        let nearby = Peer {
            local: at(now, 60),
            ..Peer::default()
        };
        assert_eq!(
            verdict(DataMode::Saver, Some(&nearby), "sync", now),
            Verdict::Allow
        );
    }

    #[test]
    fn a_failed_friend_cools_down_unless_it_is_nearby() {
        let now = Instant::now() + Duration::from_secs(3600);
        let cooling = Peer {
            inbound: at(now, 10),
            cooldown_until: Some(now + Duration::from_secs(60)),
            ..Peer::default()
        };
        assert_eq!(
            verdict(DataMode::Realtime, Some(&cooling), "sync", now),
            Verdict::Refuse("cooldown")
        );
        let nearby = Peer {
            local: at(now, 10),
            ..cooling
        };
        assert_eq!(
            verdict(DataMode::Balanced, Some(&nearby), "sync", now),
            Verdict::Allow
        );
    }

    #[test]
    fn balanced_spaces_direct_exchanges_unless_the_friend_is_nearby() {
        let now = Instant::now() + Duration::from_secs(3600);
        let just_dialled = Peer {
            last_lead: at(now, 60),
            ..Peer::default()
        };
        assert!(rate_limited(DataMode::Balanced, Some(&just_dialled), now));
        assert!(!rate_limited(DataMode::Realtime, Some(&just_dialled), now));
        let a_while_ago = Peer {
            last_lead: at(now, 16 * 60),
            ..Peer::default()
        };
        assert!(!rate_limited(DataMode::Balanced, Some(&a_while_ago), now));
        let nearby = Peer {
            last_lead: at(now, 60),
            local: at(now, 60),
            ..Peer::default()
        };
        assert!(!rate_limited(DataMode::Balanced, Some(&nearby), now));
    }

    #[test]
    fn without_a_carrier_friends_are_the_only_path_and_are_dialled() {
        assert!(!gating(false));
        assert!(gating(true));
    }

    #[test]
    fn modes_round_trip_and_floor_background_pulls() {
        for mode in [DataMode::Saver, DataMode::Balanced, DataMode::Realtime] {
            assert_eq!(DataMode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(DataMode::Saver.background_pull_floor(), None);
        assert!(DataMode::Balanced.background_pull_floor() > Some(Duration::from_secs(15 * 60)));
    }

    #[test]
    fn local_addresses_are_the_ones_that_cost_no_mobile_data() {
        let ip = |s: &str| TransportAddr::Ip(s.parse().unwrap());
        assert!(is_local(&ip("192.168.1.20:4433")));
        assert!(is_local(&ip("[fe80::1]:4433")));
        assert!(is_local(&ip("[fd00::5]:4433")));
        assert!(!is_local(&ip("172.56.105.149:38457")));
        assert!(!is_local(&ip("[2607:fb90::1]:4433")));
    }
}
