//! The stash's batch endpoint, `POST /v1/batch`: a phone's publishes and its whole pull in one
//! HTTPS request.
//!
//! ## Why
//! Over iroh, a phone reaches the stash with one QUIC connection per namespace synced, and the
//! stash dials back once per blob it is missing. Each connection cost ~20 to 40 KB of handshake
//! and path probing, measured per connection on a Pixel 10 on 2026-11-21, to carry an envelope
//! of a few hundred bytes. Every publish was a sync plus a fetch-back (~60 KB). Every pull was 18
//! trail syncs plus 14 profile syncs plus a fetch per changed friend (~1 MB). A phone publishing
//! every five minutes spent the whole 1 GB-a-month budget on overhead alone.
//!
//! In one request, the phone hands over the entries it wrote with their bytes, and names each
//! namespace it reads with the newest entry it already holds. It gets back every newer entry with
//! its bytes. The entries travel as iroh-docs `SignedEntry`s, postcard-encoded and opaque here,
//! and both replicas verify both signatures on insert exactly as they would after a sync. The
//! stash learns nothing it does not already learn from a sync: namespace ids, entry metadata, and
//! sealed bytes.
//!
//! ## Compatibility
//! A stash without the endpoint answers 404 and the phone falls back to iroh. `v` lets the format
//! change without a phone misreading an answer it does not understand: a stash answers 400 to a
//! version it does not know.

use serde::{Deserialize, Serialize};

/// The route, under the stash's HTTP base URL.
pub const BATCH_PATH: &str = "/v1/batch";
/// The format version in [`BatchRequest::v`].
pub const BATCH_VERSION: u8 = 1;
/// The content type both directions use.
pub const BATCH_CONTENT_TYPE: &str = "application/x-streetcryptid-batch";
/// The most a response carries. A response that would exceed it stops early and says so
/// ([`BatchResponse::truncated`]); the phone's next request picks up from what it got.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// The most entries one request may publish.
pub const MAX_PUBLISH: usize = 64;
/// The most namespaces one request may read.
pub const MAX_PULL: usize = 256;

/// What a phone sends.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRequest {
    /// [`BATCH_VERSION`].
    pub v: u8,
    /// Entries this phone wrote, each with its content.
    pub publish: Vec<BatchEntry>,
    /// Namespaces to read.
    pub pull: Vec<PullCursor>,
}

/// One entry and its content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchEntry {
    /// The iroh-docs namespace id.
    pub namespace: [u8; 32],
    /// A postcard-encoded iroh-docs `SignedEntry`.
    pub entry: Vec<u8>,
    /// The bytes the entry's content hash names.
    pub content: Vec<u8>,
}

/// A namespace to read, and how much of it the reader already has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullCursor {
    pub namespace: [u8; 32],
    /// The newest entry timestamp (iroh-docs microseconds) the reader holds in this namespace.
    /// Entries at or below it are not sent. `0` reads everything.
    pub since_us: u64,
}

/// What became of one published entry, in request order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublishStatus {
    /// The stash holds the entry and its bytes.
    Stored,
    /// The stash does not carry this namespace: the phone should grant it again.
    UnknownNamespace,
    /// The entry did not decode, did not belong to the namespace, its content did not match its
    /// hash, or the replica refused it. Never worth retrying as is.
    Invalid,
    /// Something on the stash's side failed. Worth retrying, through iroh if need be.
    Failed,
}

/// What the stash answers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchResponse {
    /// One per [`BatchRequest::publish`], in order.
    pub published: Vec<PublishStatus>,
    /// Every entry newer than its namespace's cursor, with its content. Entries whose bytes the
    /// stash does not hold are left out: they are not servable, and a fetch would fail too.
    pub entries: Vec<BatchEntry>,
    /// The response stopped at [`MAX_RESPONSE_BYTES`]; ask again for the rest.
    pub truncated: bool,
}

/// Errors decoding either side.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BatchError {
    #[error("batch does not decode: {0}")]
    Decode(String),
    #[error("batch version {0} is not {BATCH_VERSION}")]
    Version(u8),
    #[error("batch is over its limits")]
    TooLarge,
}

pub fn encode_request(request: &BatchRequest) -> Vec<u8> {
    postcard::to_allocvec(request).expect("a batch request always encodes")
}

/// Decode a request, rejecting an unknown version and one over the limits.
pub fn decode_request(bytes: &[u8]) -> Result<BatchRequest, BatchError> {
    let request: BatchRequest =
        postcard::from_bytes(bytes).map_err(|e| BatchError::Decode(e.to_string()))?;
    if request.v != BATCH_VERSION {
        return Err(BatchError::Version(request.v));
    }
    if request.publish.len() > MAX_PUBLISH || request.pull.len() > MAX_PULL {
        return Err(BatchError::TooLarge);
    }
    Ok(request)
}

pub fn encode_response(response: &BatchResponse) -> Vec<u8> {
    postcard::to_allocvec(response).expect("a batch response always encodes")
}

pub fn decode_response(bytes: &[u8]) -> Result<BatchResponse, BatchError> {
    postcard::from_bytes(bytes).map_err(|e| BatchError::Decode(e.to_string()))
}

/// The encoded size one entry adds to a response, for [`MAX_RESPONSE_BYTES`].
pub fn entry_cost(entry: &BatchEntry) -> usize {
    32 + entry.entry.len() + entry.content.len() + 8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: u8) -> BatchEntry {
        BatchEntry {
            namespace: [n; 32],
            entry: vec![n; 120],
            content: vec![n; 900],
        }
    }

    #[test]
    fn a_request_round_trips() {
        let request = BatchRequest {
            v: BATCH_VERSION,
            publish: vec![entry(1)],
            pull: vec![PullCursor {
                namespace: [2; 32],
                since_us: 1_795_000_000_000_000,
            }],
        };
        assert_eq!(decode_request(&encode_request(&request)), Ok(request));
    }

    #[test]
    fn a_response_round_trips() {
        let response = BatchResponse {
            published: vec![PublishStatus::Stored, PublishStatus::UnknownNamespace],
            entries: vec![entry(3), entry(4)],
            truncated: true,
        };
        assert_eq!(decode_response(&encode_response(&response)), Ok(response));
    }

    #[test]
    fn an_unknown_version_and_an_oversized_request_are_refused() {
        let mut request = BatchRequest {
            v: BATCH_VERSION + 1,
            ..BatchRequest::default()
        };
        assert_eq!(
            decode_request(&encode_request(&request)),
            Err(BatchError::Version(BATCH_VERSION + 1))
        );
        request.v = BATCH_VERSION;
        request.publish = (0..=MAX_PUBLISH as u8).map(entry).collect();
        assert_eq!(
            decode_request(&encode_request(&request)),
            Err(BatchError::TooLarge)
        );
    }

    #[test]
    fn a_pull_of_every_friend_is_a_few_hundred_bytes() {
        let request = BatchRequest {
            v: BATCH_VERSION,
            publish: Vec::new(),
            pull: (0..18)
                .map(|n| PullCursor {
                    namespace: [n; 32],
                    since_us: 1_795_000_000_000_000,
                })
                .collect(),
        };
        assert!(encode_request(&request).len() < 18 * 42);
    }
}
