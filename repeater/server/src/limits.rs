//! Resource limits for a node whose every granter is untrusted.
//!
//! The control API's only gate is a pre-shared key that ships inside the public app, so anyone
//! can hold it. And whoever grants a namespace also chose its writer: a PSK holder can mint a
//! namespace of their own, grant it, and then write whatever they like into it — any number of
//! keys, any content size. Before these limits that was an unbounded-memory hole in a RAM-only
//! process with a 512 MiB ceiling, and an OOM is not a local failure here: it wipes every grant
//! the stash holds until each phone happens to re-grant.
//!
//! So everything a granter controls is bounded, and the bounds are layered so that the one that
//! actually protects memory never depends on understanding the payload:
//!
//! * **Namespaces held** ([`Limits::max_namespaces`]) — a new grant beyond it is refused.
//! * **Bytes per entry** ([`Limits::max_entry_bytes`]) — content above it is never fetched,
//!   never accepted over HTTP, never served. The largest thing a streetCryptid build writes is a
//!   sealed repeater card (`MAX_CARD_BYTES` = 256 KiB in `modules/iroh-location/rust/src/
//!   repeater.rs`, plus a few dozen bytes of sealing); trail envelopes and profile records are a
//!   few KiB at most. The default is twice the card.
//! * **Content-bearing keys per namespace** ([`Limits::max_keys_per_namespace`]) — counted by KEY,
//!   not by hash, because the app's lanes are last-write-wins slots: one key is overwritten on
//!   every publish and accumulates hashes until the next prune, while its key count stays put. A
//!   trail namespace uses three keys per author (`fix`, `nul`, `rsy`) and a profile namespace
//!   about eight; the default leaves room for pre-LWW history a long-lived replica may still hold.
//! * **Total content** ([`Limits::max_content_bytes`]) — the real ceiling on ciphertext. A fetch
//!   that would cross it waits (with backoff) for retention to free room.
//! * **Total entry records** ([`Limits::max_record_bytes`]) — iroh-docs accepts every validly
//!   signed record into the replica, and a key has no length limit there, so records are memory
//!   too. Past the budget the namespace holding the most is evicted: dropped from the replica and
//!   refused re-grant for [`EVICTION_REFUSAL_MS`]. Under attack that is the attacker's; a phone
//!   whose namespace it was re-grants after the refusal lapses.
//!
//! Key NAMES are deliberately not allowlisted. A server-side list of the app's keys would quietly
//! stop carrying anything a new app release writes under a new key — the "a span nothing emits
//! looks like a healthy fleet" failure the root AGENTS.md warns about, moved into the data path —
//! while the count, size and budget caps above bound memory whatever the keys are called.
//!
//! Pure and iroh-free so it unit-tests in the default build.

use std::collections::HashMap;

/// A 32-byte iroh-docs namespace id.
pub type NamespaceId = [u8; 32];
/// A 32-byte digest of a docs key (the node hashes keys so a long key costs us 32 bytes, not its
/// length, to remember).
pub type KeyDigest = [u8; 32];

/// Namespaces held at once.
pub const DEFAULT_MAX_NAMESPACES: usize = 2048;
/// Largest single content blob: twice the sealed repeater card, the biggest legitimate entry.
pub const DEFAULT_MAX_ENTRY_BYTES: u64 = 512 * 1024;
/// Content-bearing keys per namespace.
pub const DEFAULT_MAX_KEYS_PER_NAMESPACE: usize = 256;
/// Total ciphertext held: a quarter of the 512 MiB container limit.
pub const DEFAULT_MAX_CONTENT_BYTES: u64 = 128 * 1024 * 1024;
/// Total entry records, by [`record_cost`].
pub const DEFAULT_MAX_RECORD_BYTES: u64 = 64 * 1024 * 1024;
/// Content fetches in flight at once, across every namespace.
pub const DEFAULT_FETCH_CONCURRENCY: usize = 8;
/// Content fetches in flight for one namespace. Low on purpose: a namespace full of unfetchable
/// entries can then hold at most this many of the global slots, whatever it writes.
pub const FETCH_PER_NAMESPACE: usize = 2;
/// How long an evicted namespace's re-grant is refused.
pub const EVICTION_REFUSAL_MS: u64 = 6 * 60 * 60 * 1000;
/// What one entry record is charged on top of its key: the signed entry (namespace, author, key
/// hash, length, timestamp, two signatures) plus the replica's own indexing. An estimate; the
/// budget is about order of magnitude, not bytes.
pub const RECORD_OVERHEAD_BYTES: u64 = 256;

/// The resolved limits a node runs with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_namespaces: usize,
    pub max_entry_bytes: u64,
    pub max_keys_per_namespace: usize,
    pub max_content_bytes: u64,
    pub max_record_bytes: u64,
    pub fetch_concurrency: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_namespaces: DEFAULT_MAX_NAMESPACES,
            max_entry_bytes: DEFAULT_MAX_ENTRY_BYTES,
            max_keys_per_namespace: DEFAULT_MAX_KEYS_PER_NAMESPACE,
            max_content_bytes: DEFAULT_MAX_CONTENT_BYTES,
            max_record_bytes: DEFAULT_MAX_RECORD_BYTES,
            fetch_concurrency: DEFAULT_FETCH_CONCURRENCY,
        }
    }
}

/// What one entry record costs against [`Limits::max_record_bytes`].
pub fn record_cost(key_len: usize) -> u64 {
    RECORD_OVERHEAD_BYTES.saturating_add(key_len as u64)
}

/// How long to wait before fetching an entry's content again after `attempts` tries.
///
/// The same shape as the phone's `docs::stranded_retry_delay`: quick while the author is likely
/// still connected finishing its own sync (500 ms doubling to a minute), then slow once it has
/// clearly gone — an entry nobody can serve must not cost a dial a minute for the life of the
/// process, and must not keep a fetch slot busy that a fresh entry could use. Phones upload their
/// bytes over HTTP (`/v1/batch`) as well, so a slow pull only matters for content no phone
/// uploaded.
pub fn fetch_retry_delay_ms(attempts: u32) -> u64 {
    const BASE_MS: u64 = 500;
    const FAST_CEILING_MS: u64 = 60_000;
    /// Attempts before the author counts as gone: ~8 minutes of fast retries.
    const FAST_ATTEMPTS: u32 = 12;
    const SLOW_MS: u64 = 15 * 60_000;
    const SLOW_CEILING_MS: u64 = 2 * 60 * 60_000;
    if attempts < FAST_ATTEMPTS {
        return BASE_MS
            .saturating_mul(1u64 << attempts.min(7))
            .min(FAST_CEILING_MS);
    }
    SLOW_MS
        .saturating_mul(1u64 << (attempts - FAST_ATTEMPTS).min(4))
        .min(SLOW_CEILING_MS)
}

/// One entry waiting for its content, as the fetch scheduler sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchCandidate {
    pub namespace: NamespaceId,
    pub attempts: u32,
    pub next_attempt_ms: u64,
}

/// Choose which due candidates to start fetching now, as indices into `candidates`.
///
/// Fewest attempts first: a fresh entry is the one most likely to succeed (its author was just
/// connected), and an entry that has failed many times is the one a hostile namespace would fill
/// the queue with. Then at most [`FETCH_PER_NAMESPACE`] per namespace (counting fetches already in
/// flight) and `max_total` overall, so one namespace cannot starve the others whatever it writes.
pub fn pick_fetches(
    candidates: &[FetchCandidate],
    in_flight: &HashMap<NamespaceId, usize>,
    max_total: usize,
) -> Vec<usize> {
    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_by_key(|&i| (candidates[i].attempts, candidates[i].next_attempt_ms));
    let mut total: usize = in_flight.values().sum();
    let mut per_ns = in_flight.clone();
    let mut picked = Vec::new();
    for i in order {
        if total >= max_total {
            break;
        }
        let ns = per_ns.entry(candidates[i].namespace).or_insert(0);
        if *ns >= FETCH_PER_NAMESPACE {
            continue;
        }
        *ns += 1;
        total += 1;
        picked.push(i);
    }
    picked
}

/// What [`RecordLedger::observe`] decided about one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observed {
    /// Whether this record's content may be tracked, fetched and served. False when it is a new
    /// content-bearing key beyond [`Limits::max_keys_per_namespace`].
    pub content_admitted: bool,
    /// Set when the record budget is now exceeded: the namespace to evict (the largest).
    pub evict: Option<NamespaceId>,
}

#[derive(Debug, Clone, Copy)]
struct KeyRecord {
    cost: u64,
    content_admitted: bool,
}

#[derive(Debug, Default)]
struct NamespaceRecords {
    keys: HashMap<KeyDigest, KeyRecord>,
    cost: u64,
    admitted: usize,
}

/// Every record the replica holds, by namespace and record slot — what the record budget and the
/// per-namespace key cap are counted against. A docs replica keeps one record per (key, docs
/// author), so the node digests BOTH into the [`KeyDigest`]: keyed by the key alone, a writer
/// could add records without limit by signing the same key with fresh authors. Our lanes are
/// last-write-wins, so an overwrite replaces a record rather than adding one.
#[derive(Debug, Default)]
pub struct RecordLedger {
    by_namespace: HashMap<NamespaceId, NamespaceRecords>,
    total: u64,
}

impl RecordLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Note a record under `key` in `ns`, `key_len` bytes long, carrying content or not.
    pub fn observe(
        &mut self,
        ns: NamespaceId,
        key: KeyDigest,
        key_len: usize,
        has_content: bool,
        limits: &Limits,
    ) -> Observed {
        let cost = record_cost(key_len);
        let records = self.by_namespace.entry(ns).or_default();
        let content_admitted = match records.keys.get_mut(&key) {
            Some(existing) => {
                // An overwrite: same key, so the same record slot. A key admitted once stays
                // admitted — refusing the next fix on a lane we already serve would be a hole
                // in a friend's dot, not a bound.
                if !existing.content_admitted
                    && has_content
                    && records.admitted < limits.max_keys_per_namespace
                {
                    existing.content_admitted = true;
                    records.admitted += 1;
                }
                existing.content_admitted
            }
            None => {
                let admitted = has_content && records.admitted < limits.max_keys_per_namespace;
                if admitted {
                    records.admitted += 1;
                }
                records.keys.insert(
                    key,
                    KeyRecord {
                        cost,
                        content_admitted: admitted,
                    },
                );
                records.cost = records.cost.saturating_add(cost);
                self.total = self.total.saturating_add(cost);
                admitted
            }
        };
        // A tombstone (empty content) admits nothing to fetch, but it is not refused either.
        let content_admitted = content_admitted || !has_content;
        let evict = if self.total > limits.max_record_bytes {
            self.largest()
        } else {
            None
        };
        Observed {
            content_admitted,
            evict,
        }
    }

    /// The namespace holding the most record bytes.
    fn largest(&self) -> Option<NamespaceId> {
        self.by_namespace
            .iter()
            .max_by_key(|(_, records)| records.cost)
            .map(|(ns, _)| *ns)
    }

    /// Stop counting a namespace the node no longer holds.
    pub fn forget_namespace(&mut self, ns: &NamespaceId) {
        if let Some(records) = self.by_namespace.remove(ns) {
            self.total = self.total.saturating_sub(records.cost);
        }
    }

    /// Record bytes held in total.
    pub fn total_cost(&self) -> u64 {
        self.total
    }

    /// Distinct keys held for `ns`.
    pub fn key_count(&self, ns: &NamespaceId) -> usize {
        self.by_namespace.get(ns).map_or(0, |r| r.keys.len())
    }
}

/// Namespaces evicted for breaching a limit, and until when their re-grant is refused. Bounded:
/// past `cap` entries expired ones are dropped, and if none has expired the new one is not
/// remembered (the eviction itself already happened; only the refusal is lost).
#[derive(Debug, Default)]
pub struct EvictionList {
    until: HashMap<NamespaceId, u64>,
}

impl EvictionList {
    pub fn insert(&mut self, ns: NamespaceId, now_ms: u64, cap: usize) {
        if self.until.len() >= cap {
            self.until.retain(|_, until| *until > now_ms);
        }
        if self.until.len() < cap {
            self.until
                .insert(ns, now_ms.saturating_add(EVICTION_REFUSAL_MS));
        }
    }

    pub fn is_refused(&self, ns: &NamespaceId, now_ms: u64) -> bool {
        self.until.get(ns).is_some_and(|until| *until > now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS_A: NamespaceId = [1; 32];
    const NS_B: NamespaceId = [2; 32];

    fn key(n: u8) -> KeyDigest {
        [n; 32]
    }

    #[test]
    fn the_default_entry_cap_holds_the_largest_legitimate_entry() {
        // The sealed repeater card: MAX_CARD_BYTES in the mobile crate, plus sealing overhead.
        const MAX_CARD_BYTES: u64 = 256 * 1024;
        assert!(Limits::default().max_entry_bytes >= MAX_CARD_BYTES + 1024);
        assert!(
            Limits::default().max_content_bytes + Limits::default().max_record_bytes
                < 512 * 1024 * 1024 / 2,
            "the default budgets must leave the container's other half for the node itself"
        );
    }

    #[test]
    fn retry_delay_is_fast_then_slow_and_bounded() {
        assert_eq!(fetch_retry_delay_ms(0), 500);
        assert_eq!(fetch_retry_delay_ms(1), 1_000);
        assert_eq!(fetch_retry_delay_ms(11), 60_000);
        assert_eq!(fetch_retry_delay_ms(12), 15 * 60_000);
        assert_eq!(fetch_retry_delay_ms(13), 30 * 60_000);
        assert_eq!(fetch_retry_delay_ms(u32::MAX), 2 * 60 * 60_000);
        let mut last = 0;
        for attempts in 0..40 {
            let delay = fetch_retry_delay_ms(attempts);
            assert!(delay >= last, "the delay never shrinks as attempts grow");
            last = delay;
        }
    }

    #[test]
    fn a_hostile_namespace_cannot_take_every_fetch_slot() {
        // Twenty stale entries in A, one fresh entry in B.
        let mut candidates: Vec<FetchCandidate> = (0..20)
            .map(|i| FetchCandidate {
                namespace: NS_A,
                attempts: 3,
                next_attempt_ms: i,
            })
            .collect();
        candidates.push(FetchCandidate {
            namespace: NS_B,
            attempts: 0,
            next_attempt_ms: 100,
        });
        let picked = pick_fetches(&candidates, &HashMap::new(), 8);
        assert_eq!(picked[0], 20, "the fresh entry goes first");
        assert_eq!(
            picked
                .iter()
                .filter(|&&i| candidates[i].namespace == NS_A)
                .count(),
            FETCH_PER_NAMESPACE
        );
    }

    #[test]
    fn fetches_already_in_flight_count_against_both_limits() {
        let candidates = [
            FetchCandidate {
                namespace: NS_A,
                attempts: 0,
                next_attempt_ms: 0,
            },
            FetchCandidate {
                namespace: NS_B,
                attempts: 0,
                next_attempt_ms: 0,
            },
        ];
        let in_flight = HashMap::from([(NS_A, FETCH_PER_NAMESPACE)]);
        assert_eq!(pick_fetches(&candidates, &in_flight, 8), vec![1]);
        let full = HashMap::from([(NS_A, 1), ([3; 32], 1)]);
        assert!(pick_fetches(&candidates, &full, 2).is_empty());
    }

    #[test]
    fn keys_beyond_the_cap_are_refused_content_but_overwrites_are_not() {
        let limits = Limits {
            max_keys_per_namespace: 2,
            ..Limits::default()
        };
        let mut ledger = RecordLedger::new();
        assert!(
            ledger
                .observe(NS_A, key(1), 68, true, &limits)
                .content_admitted
        );
        assert!(
            ledger
                .observe(NS_A, key(2), 68, true, &limits)
                .content_admitted
        );
        assert!(
            !ledger
                .observe(NS_A, key(3), 68, true, &limits)
                .content_admitted
        );
        // The lane we already serve keeps being served.
        assert!(
            ledger
                .observe(NS_A, key(1), 68, true, &limits)
                .content_admitted
        );
        // Tombstones are not content and are never refused.
        assert!(
            ledger
                .observe(NS_A, key(4), 68, false, &limits)
                .content_admitted
        );
        // Another namespace has its own allowance.
        assert!(
            ledger
                .observe(NS_B, key(3), 68, true, &limits)
                .content_admitted
        );
        assert_eq!(ledger.key_count(&NS_A), 4);
    }

    #[test]
    fn overwrites_cost_nothing_more() {
        let limits = Limits::default();
        let mut ledger = RecordLedger::new();
        ledger.observe(NS_A, key(1), 68, true, &limits);
        let once = ledger.total_cost();
        for _ in 0..100 {
            ledger.observe(NS_A, key(1), 68, true, &limits);
        }
        assert_eq!(ledger.total_cost(), once);
        assert_eq!(once, record_cost(68));
    }

    #[test]
    fn past_the_record_budget_the_largest_namespace_is_named() {
        let limits = Limits {
            max_record_bytes: record_cost(10) * 5,
            ..Limits::default()
        };
        let mut ledger = RecordLedger::new();
        ledger.observe(NS_B, key(1), 10, true, &limits);
        for n in 0..4 {
            assert_eq!(ledger.observe(NS_A, key(n), 10, true, &limits).evict, None);
        }
        // A sixth record crosses the budget; A holds four of them.
        assert_eq!(
            ledger.observe(NS_B, key(9), 10, true, &limits).evict,
            Some(NS_A)
        );
        ledger.forget_namespace(&NS_A);
        assert_eq!(ledger.total_cost(), record_cost(10) * 2);
        assert_eq!(ledger.key_count(&NS_A), 0);
    }

    #[test]
    fn a_long_key_costs_its_length() {
        let limits = Limits {
            max_record_bytes: 10_000,
            ..Limits::default()
        };
        let mut ledger = RecordLedger::new();
        assert_eq!(
            ledger.observe(NS_A, key(1), 20_000, false, &limits).evict,
            Some(NS_A),
            "one record with a huge key is enough to evict its namespace"
        );
    }

    #[test]
    fn eviction_refusals_expire_and_stay_bounded() {
        let mut list = EvictionList::default();
        list.insert(NS_A, 0, 2);
        assert!(list.is_refused(&NS_A, 1));
        assert!(!list.is_refused(&NS_A, EVICTION_REFUSAL_MS));
        list.insert(NS_B, 1, 2);
        list.insert([3; 32], 2, 2);
        assert!(
            !list.is_refused(&[3; 32], 3),
            "a full list remembers no more"
        );
        list.insert([3; 32], EVICTION_REFUSAL_MS + 2, 2);
        assert!(
            list.is_refused(&[3; 32], EVICTION_REFUSAL_MS + 3),
            "expired entries make room"
        );
    }
}
