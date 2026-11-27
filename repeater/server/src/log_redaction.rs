//! Last-line protection against network addresses and stable identifiers reaching logs.

use std::net::{IpAddr, SocketAddr};

const REDACTED: &str = "[REDACTED]";

/// Redact IP addresses and long identity-like tokens from a fully formatted log event.
pub fn redact_log_line(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut ranges = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        if is_network_char(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_network_char(bytes[i]) {
                i += 1;
            }
            let candidate = &input[start..i];
            if candidate.parse::<IpAddr>().is_ok() || candidate.parse::<SocketAddr>().is_ok() {
                ranges.push((start, i));
            }
        } else {
            i += 1;
        }
    }

    i = 0;
    while i < bytes.len() {
        if is_opaque_char(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_opaque_char(bytes[i]) {
                i += 1;
            }
            let candidate = &input[start..i];
            if candidate.len() >= 32
                && (candidate.bytes().any(|b| b.is_ascii_digit())
                    || candidate.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                ranges.push((start, i));
            }
        } else {
            i += 1;
        }
    }

    if ranges.is_empty() {
        return input.to_owned();
    }

    ranges.sort_unstable();
    let mut output = String::with_capacity(input.len());
    let mut copied = 0;
    for (start, end) in ranges {
        if end <= copied {
            continue;
        }
        let start = start.max(copied);
        output.push_str(&input[copied..start]);
        output.push_str(REDACTED);
        copied = end;
    }
    output.push_str(&input[copied..]);
    output
}

/// Length of the `sc.*` join-key form (`telemetry::short_hex`: the first five bytes as hex).
const SHORT_ID_CHARS: usize = 10;

/// The request path as telemetry may carry it: every segment long enough to be an id
/// (`/v1/namespaces/{namespace}/content/{hash}`) cut to its first ten characters.
///
/// A full namespace id is half of a read capability (the other half is ticket material the app
/// hands out alongside it), and either id is a stable handle that links one user's requests
/// across days. Ten hex chars of a namespace are exactly the `sc.namespace` join key the phones
/// and the rest of the stash's spans use, so a path still joins in Tempo; a segment that is not
/// plain alphanumerics (it cannot be one of ours) is dropped whole.
pub fn redact_url_path(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if segment.len() < 32 {
                segment
            } else if segment.bytes().all(|b| b.is_ascii_alphanumeric()) {
                &segment[..SHORT_ID_CHARS]
            } else {
                REDACTED
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn is_network_char(byte: u8) -> bool {
    byte.is_ascii_hexdigit() || matches!(byte, b'.' | b':')
}

fn is_opaque_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'+' | b'/' | b'=')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_ipv4_and_ports() {
        let line = "peer=192.0.2.44 remote=198.51.100.8:443";
        let redacted = redact_log_line(line);
        assert_eq!(redacted, "peer=[REDACTED] remote=[REDACTED]");
    }

    #[test]
    fn redacts_ipv6_addresses() {
        let line = "direct=2001:db8::8 relay=[2001:db8::9]:443";
        let redacted = redact_log_line(line);
        assert!(!redacted.contains("2001:db8"));
    }

    #[test]
    fn redacts_identity_like_values() {
        let line = "node=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef token=AbCdEfGhIjKlMnOpQrStUvWxYz012345";
        let redacted = redact_log_line(line);
        assert_eq!(redacted.matches(REDACTED).count(), 2);
        assert!(!redacted.contains("0123456789abcdef"));
        assert!(!redacted.contains("AbCdEfGh"));
    }

    #[test]
    fn url_paths_keep_only_the_join_key_of_an_id() {
        let ns = "0123456789abcdef".repeat(4);
        let hash = "fedcba9876543210".repeat(4);
        assert_eq!(
            redact_url_path(&format!("/v1/namespaces/{ns}/content/{hash}")),
            "/v1/namespaces/0123456789/content/fedcba9876"
        );
        assert_eq!(
            redact_url_path(&format!("/v1/namespaces/{ns}/subscription")),
            "/v1/namespaces/0123456789/subscription"
        );
        assert_eq!(redact_url_path("/v1/batch"), "/v1/batch");
        assert_eq!(redact_url_path("/healthz"), "/healthz");
        let odd = format!("{}%2F{}", "a".repeat(20), "b".repeat(20));
        assert_eq!(
            redact_url_path(&format!("/v1/namespaces/{odd}")),
            format!("/v1/namespaces/{REDACTED}")
        );
    }

    #[test]
    fn preserves_normal_diagnostics() {
        let line = "2026-07-12T19:07:49Z stash: pruned 12 expired entries";
        assert_eq!(redact_log_line(line), line);
    }
}
