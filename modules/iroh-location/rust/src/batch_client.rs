//! The phone's half of the stash's `POST /v1/batch` (`streetcryptid_repeater::stash_batch`).
//!
//! One process-wide HTTPS client, so consecutive requests reuse one connection while it stays open
//! (the app on screen pulls every 20 to 90 s) instead of paying a TLS handshake each time. A stash
//! that predates the endpoint answers 404. That is remembered for an hour, so the iroh path is
//! used without asking again on every publish.

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use streetcryptid_repeater::stash_batch::{
    decode_response, encode_request, BatchRequest, BatchResponse, BATCH_CONTENT_TYPE, BATCH_PATH,
};

/// How long a stash that answered 404 is left alone before it is asked again.
const UNSUPPORTED_BACKOFF: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, thiserror::Error)]
pub(crate) enum BatchFailure {
    /// This stash has no batch endpoint (yet): use iroh.
    #[error("the stash has no batch endpoint")]
    Unsupported,
    #[error("the stash answered {0}")]
    Status(u16),
    #[error("could not reach the stash: {0}")]
    Transport(String),
    #[error("the stash's answer does not decode: {0}")]
    Decode(String),
}

fn client() -> Option<&'static reqwest::Client> {
    static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                // Long enough to span the app's on-screen pull interval, so those reuse one TLS
                // session rather than each opening their own.
                .pool_idle_timeout(Duration::from_secs(120))
                .build()
                .ok()
        })
        .as_ref()
}

static UNSUPPORTED: Mutex<Option<(String, Instant)>> = Mutex::new(None);

fn known_unsupported(base_url: &str) -> bool {
    let guard = UNSUPPORTED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .as_ref()
        .is_some_and(|(url, at)| url == base_url && at.elapsed() < UNSUPPORTED_BACKOFF)
}

fn note_unsupported(base_url: &str) {
    *UNSUPPORTED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
        Some((base_url.to_owned(), Instant::now()));
}

/// Send one batch. `timeout` bounds the whole exchange. Returns the answer and the bytes that went
/// each way (bodies only).
pub(crate) async fn post(
    base_url: &str,
    psk: Option<&str>,
    request: &BatchRequest,
    timeout: Duration,
) -> Result<(BatchResponse, usize, usize), BatchFailure> {
    if known_unsupported(base_url) {
        return Err(BatchFailure::Unsupported);
    }
    let Some(client) = client() else {
        return Err(BatchFailure::Transport("no HTTP client".into()));
    };
    let body = encode_request(request);
    let sent = body.len();
    let mut builder = client
        .post(format!("{}{BATCH_PATH}", base_url.trim_end_matches('/')))
        .timeout(timeout)
        .header(reqwest::header::CONTENT_TYPE, BATCH_CONTENT_TYPE)
        .body(body);
    if let Some(psk) = psk {
        builder = builder.bearer_auth(psk);
    }
    let response = builder
        .send()
        .await
        .map_err(|e| BatchFailure::Transport(e.to_string()))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::METHOD_NOT_ALLOWED
    {
        note_unsupported(base_url);
        return Err(BatchFailure::Unsupported);
    }
    if !status.is_success() {
        return Err(BatchFailure::Status(status.as_u16()));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|e| BatchFailure::Transport(e.to_string()))?;
    let received = bytes.len();
    let decoded = decode_response(&bytes).map_err(|e| BatchFailure::Decode(e.to_string()))?;
    Ok((decoded, sent, received))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stash_without_the_endpoint_is_left_alone_for_a_while() {
        let url = "https://stash.invalid";
        assert!(!known_unsupported(url));
        note_unsupported(url);
        assert!(known_unsupported(url));
        assert!(!known_unsupported("https://other.invalid"));
    }
}
