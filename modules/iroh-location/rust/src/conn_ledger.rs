//! Which connections the bytes go to: QUIC bytes per (ALPN, remote, side), on the `net.conns`
//! span the `net.health` pulse emits beside its own.
//!
//! ## The hole this fills
//! On 2026-11-21 a Pixel 10 had used 34 GB of mobile UPLOAD in a week. `net.health`'s `ep.*`
//! counters showed when: about 47 MB went out over direct IP on every friend pull (every 15 min
//! parked, every 5 otherwise), with about 1 MB coming back. They could not show where. Those
//! counters belong to the whole endpoint. The stash's own network counters ruled the stash out,
//! and the other phones' receive counters ruled out every phone in the fleet. That left nothing
//! that could name a destination.
//!
//! So [`ConnLedgerHook`] is installed on the node's endpoint:
//! - `before_connect` counts every dial by (ALPN, remote);
//! - `after_handshake` registers every connection, inbound and outbound, with a weak handle
//!   (never a strong one, which would keep a connection alive);
//! - the five-minute pulse reads each open connection's `ConnectionStats` and books the bytes
//!   since the last reading against its (ALPN, remote, side) row;
//! - a closed connection books what was left, and if it moved more than [`BIG_CONN_BYTES`] it
//!   also gets a `conn.closed` span of its own with its totals and close reason.
//!
//! `net.conns` then reports the heaviest rows (`conn.top_tx`, `conn.top_attempts`,
//! `conn.by_alpn`), the totals, and `conn.unattributed_tx`. The last is the endpoint's own send
//! count minus everything the connections account for. A large unattributed share is traffic no
//! connection owns: QUIC handshakes that never completed, relay framing, net_report probes. That
//! is an answer too.
//!
//! The counts come from noq's per-connection UDP accounting, so they cover every transport a
//! connection used (direct IP, relay, BLE). Rows carry ALPNs, short endpoint ids and byte counts,
//! never content.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use iroh::endpoint::{
    AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks, Side,
    WeakConnectionHandle,
};
use iroh::EndpointAddr;

/// A connection that moved more than this, either way, gets its own `conn.closed` span when it
/// ends. Normal syncs and pushes are kilobytes, so anything this size is what we are looking for.
pub(crate) const BIG_CONN_BYTES: u64 = 1 << 20;
/// How many rows each summary keeps.
const TOP_ROWS: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Key {
    alpn: String,
    remote: String,
    /// `out` (we dialled) or `in`.
    side: &'static str,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Row {
    attempts: u64,
    handshakes: u64,
    closed: u64,
    tx: u64,
    rx: u64,
    lost: u64,
}

/// The cumulative counts already booked for one open connection.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Booked {
    tx: u64,
    rx: u64,
    lost: u64,
}

struct Live {
    key: Key,
    weak: WeakConnectionHandle,
    booked: Booked,
    opened: Instant,
}

#[derive(Default)]
struct State {
    window: BTreeMap<Key, Row>,
    live: HashMap<u64, Live>,
    next_id: u64,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);
/// The runtime the node runs on, for `runtime.tokio_tasks` (the pulse calls in from a platform
/// thread, outside it).
static RUNTIME: OnceLock<tokio::runtime::Handle> = OnceLock::new();

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let mut guard = STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(guard.get_or_insert_with(State::default))
}

fn alpn_label(alpn: &[u8]) -> String {
    let label = String::from_utf8_lossy(alpn);
    let label = label.trim_matches('/');
    if label.is_empty() {
        "none".to_owned()
    } else {
        label.chars().take(40).collect()
    }
}

fn side_label(side: Side) -> &'static str {
    match side {
        Side::Client => "out",
        Side::Server => "in",
    }
}

/// What the stats say now, minus what was already booked. Saturating, so a reading that went
/// backwards (it cannot, but a race between the pulse and the close task could look like it)
/// books nothing instead of wrapping.
fn unbooked(now: Booked, booked: Booked) -> Booked {
    Booked {
        tx: now.tx.saturating_sub(booked.tx),
        rx: now.rx.saturating_sub(booked.rx),
        lost: now.lost.saturating_sub(booked.lost),
    }
}

fn add(row: &mut Row, delta: Booked) {
    row.tx += delta.tx;
    row.rx += delta.rx;
    row.lost += delta.lost;
}

fn booked_from(stats: &iroh::endpoint::ConnectionStats) -> Booked {
    Booked {
        tx: stats.udp_tx.bytes,
        rx: stats.udp_rx.bytes,
        lost: stats.lost_bytes,
    }
}

/// The hook. Cheap to clone: everything it writes is process-wide.
#[derive(Debug, Clone, Default)]
pub(crate) struct ConnLedgerHook;

/// The hook to install on the node's endpoint. Call it from the node's runtime, so the pulse can
/// find that runtime later.
pub(crate) fn hook() -> ConnLedgerHook {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let _ = RUNTIME.set(handle);
    }
    ConnLedgerHook
}

impl EndpointHooks for ConnLedgerHook {
    async fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        let key = Key {
            alpn: alpn_label(alpn),
            remote: crate::telemetry::short_hex(remote_addr.id.as_bytes()),
            side: "out",
        };
        with_state(|s| s.window.entry(key).or_default().attempts += 1);
        BeforeConnectOutcome::Accept
    }

    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        let key = Key {
            alpn: alpn_label(conn.alpn()),
            remote: crate::telemetry::short_hex(conn.remote_id().as_bytes()),
            side: side_label(conn.side()),
        };
        let weak = conn.weak_handle();
        // Registered while `conn` is still a strong reference, so the close is always delivered.
        let closed = weak.closed();
        let id = with_state(|s| {
            s.window.entry(key.clone()).or_default().handshakes += 1;
            let id = s.next_id;
            s.next_id += 1;
            s.live.insert(
                id,
                Live {
                    key,
                    weak,
                    booked: Booked::default(),
                    opened: Instant::now(),
                },
            );
            id
        });
        tokio::spawn(async move {
            let closed = closed.await;
            finish(id, closed);
        });
        AfterHandshakeOutcome::accept()
    }
}

/// Book what a closed connection had left, and give a big one its own span.
fn finish(id: u64, closed: Option<iroh::endpoint::Closed>) {
    let Some((live, delta)) = with_state(|s| {
        let live = s.live.remove(&id)?;
        let delta = closed
            .as_ref()
            .map(|c| unbooked(booked_from(&c.stats), live.booked))
            .unwrap_or_default();
        let row = s.window.entry(live.key.clone()).or_default();
        row.closed += 1;
        add(row, delta);
        Some((live, delta))
    }) else {
        return;
    };
    let total = Booked {
        tx: live.booked.tx + delta.tx,
        rx: live.booked.rx + delta.rx,
        lost: live.booked.lost + delta.lost,
    };
    if total.tx.max(total.rx) < BIG_CONN_BYTES {
        return;
    }
    let reason = closed
        .map(|c| truncate(&c.reason.to_string()))
        .unwrap_or_default();
    let span = tracing::info_span!(
        "conn.closed",
        conn.alpn = live.key.alpn.as_str(),
        sc.peer = live.key.remote.as_str(),
        conn.side = live.key.side,
        conn.tx_bytes = total.tx,
        conn.rx_bytes = total.rx,
        conn.lost_bytes = total.lost,
        conn.duration_ms = live.opened.elapsed().as_millis() as u64,
        conn.reason = reason.as_str(),
    );
    drop(span.entered());
}

fn truncate(s: &str) -> String {
    s.chars().take(160).collect()
}

/// Read every open connection's stats into the window. Called by the pulse.
fn sample_live() {
    // Upgrade outside the lock: `stats()` takes the connection's own lock.
    let handles: Vec<(u64, WeakConnectionHandle)> = with_state(|s| {
        s.live
            .iter()
            .map(|(id, live)| (*id, live.weak.clone()))
            .collect()
    });
    let readings: Vec<(u64, Booked)> = handles
        .into_iter()
        .filter_map(|(id, weak)| weak.upgrade().map(|conn| (id, booked_from(&conn.stats()))))
        .collect();
    with_state(|s| {
        for (id, now) in readings {
            // Gone already: the close task booked it, from the final stats.
            let Some(live) = s.live.get_mut(&id) else {
                continue;
            };
            let delta = unbooked(now, live.booked);
            live.booked = now;
            let key = live.key.clone();
            add(s.window.entry(key).or_default(), delta);
        }
    });
}

/// One window's worth, as `net.conns` reports it.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct Window {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub lost_bytes: u64,
    pub attempts: u64,
    pub handshakes: u64,
    pub closed: u64,
    /// Connections open right now. A number that only climbs is a connection leak.
    pub live: u64,
    /// `alpn remote side tx=… rx=… hs=… att=…; …`, heaviest by tx first.
    pub top_tx: String,
    /// `alpn remote=dials; …`, most dialled first.
    pub top_attempts: String,
    /// `alpn tx=… rx=… hs=…; …` summed over remotes.
    pub by_alpn: String,
}

fn mib(bytes: u64) -> String {
    if bytes >= 1 << 20 {
        format!("{:.1}M", bytes as f64 / (1u64 << 20) as f64)
    } else {
        format!("{}K", bytes.div_ceil(1024))
    }
}

/// Sample the open connections, then take (and reset) the window.
pub(crate) fn take_window() -> Window {
    sample_live();
    let (rows, live) = with_state(|s| (std::mem::take(&mut s.window), s.live.len() as u64));
    summarize(rows, live)
}

fn summarize(rows: BTreeMap<Key, Row>, live: u64) -> Window {
    let mut w = Window {
        live,
        ..Window::default()
    };
    let mut alpns: BTreeMap<&str, Row> = BTreeMap::new();
    for (key, row) in &rows {
        w.tx_bytes += row.tx;
        w.rx_bytes += row.rx;
        w.lost_bytes += row.lost;
        w.attempts += row.attempts;
        w.handshakes += row.handshakes;
        w.closed += row.closed;
        let a = alpns.entry(key.alpn.as_str()).or_default();
        a.tx += row.tx;
        a.rx += row.rx;
        a.handshakes += row.handshakes;
        a.attempts += row.attempts;
    }

    let mut by_tx: Vec<(&Key, &Row)> = rows.iter().filter(|(_, r)| r.tx + r.rx > 0).collect();
    by_tx.sort_by(|a, b| b.1.tx.cmp(&a.1.tx).then_with(|| b.1.rx.cmp(&a.1.rx)));
    w.top_tx = by_tx
        .iter()
        .take(TOP_ROWS)
        .map(|(k, r)| {
            format!(
                "{} {} {} tx={} rx={} hs={} att={}",
                k.alpn,
                k.remote,
                k.side,
                mib(r.tx),
                mib(r.rx),
                r.handshakes,
                r.attempts
            )
        })
        .collect::<Vec<_>>()
        .join("; ");

    let mut by_attempts: Vec<(&Key, &Row)> = rows.iter().filter(|(_, r)| r.attempts > 0).collect();
    by_attempts.sort_by(|a, b| b.1.attempts.cmp(&a.1.attempts));
    w.top_attempts = by_attempts
        .iter()
        .take(TOP_ROWS)
        .map(|(k, r)| format!("{} {}={}", k.alpn, k.remote, r.attempts))
        .collect::<Vec<_>>()
        .join("; ");

    let mut alpn_rows: Vec<(&str, Row)> = alpns.into_iter().collect();
    alpn_rows.sort_by(|a, b| b.1.tx.cmp(&a.1.tx));
    w.by_alpn = alpn_rows
        .iter()
        .map(|(alpn, r)| {
            format!(
                "{alpn} tx={} rx={} hs={} att={}",
                mib(r.tx),
                mib(r.rx),
                r.handshakes,
                r.attempts
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    w
}

/// Tasks alive on the node's runtime (`runtime.tokio_tasks` on `net.conns`). A number that only
/// climbs is a task leak, and every leaked task holds its future's memory.
pub(crate) fn tokio_alive_tasks() -> Option<u64> {
    RUNTIME
        .get()
        .map(|handle| handle.metrics().num_alive_tasks() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(alpn: &str, remote: &str, side: &'static str) -> Key {
        Key {
            alpn: alpn.into(),
            remote: remote.into(),
            side,
        }
    }

    #[test]
    fn labels_alpns_without_their_slashes() {
        assert_eq!(alpn_label(b"/iroh-sync/1"), "iroh-sync/1");
        assert_eq!(alpn_label(b""), "none");
    }

    #[test]
    fn books_only_what_was_not_booked_and_never_wraps() {
        let booked = Booked {
            tx: 100,
            rx: 50,
            lost: 0,
        };
        let now = Booked {
            tx: 350,
            rx: 40,
            lost: 7,
        };
        assert_eq!(
            unbooked(now, booked),
            Booked {
                tx: 250,
                rx: 0,
                lost: 7
            }
        );
    }

    #[test]
    fn summarizes_heaviest_first_with_totals_and_alpn_sums() {
        let mut rows = BTreeMap::new();
        rows.insert(
            key("iroh-sync/1", "aaaaaaaaaa", "out"),
            Row {
                attempts: 300,
                handshakes: 270,
                closed: 270,
                tx: 47 << 20,
                rx: 1 << 20,
                lost: 0,
            },
        );
        rows.insert(
            key("iroh-bytes/4", "bbbbbbbbbb", "in"),
            Row {
                handshakes: 3,
                closed: 3,
                tx: 2048,
                rx: 512,
                ..Row::default()
            },
        );
        rows.insert(
            key("iroh-sync/1", "cccccccccc", "out"),
            Row {
                attempts: 400,
                ..Row::default()
            },
        );
        let w = summarize(rows, 2);
        assert_eq!(w.tx_bytes, (47 << 20) + 2048);
        assert_eq!(w.attempts, 700);
        assert_eq!(w.handshakes, 273);
        assert_eq!(w.live, 2);
        assert!(
            w.top_tx
                .starts_with("iroh-sync/1 aaaaaaaaaa out tx=47.0M rx=1.0M hs=270 att=300"),
            "{}",
            w.top_tx
        );
        // A row that only dialled moved nothing, so it is not in the byte ranking...
        assert!(!w.top_tx.contains("cccccccccc"));
        // ...but it leads the dial ranking.
        assert!(w.top_attempts.starts_with("iroh-sync/1 cccccccccc=400"));
        assert!(w.by_alpn.starts_with("iroh-sync/1 tx=47.0M"));
    }
}
