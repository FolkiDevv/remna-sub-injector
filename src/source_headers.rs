//! The headers the injector puts on its own request when a links source is an http(s) URL.
//!
//! A source is usually another subscription panel, and a panel answers a request by who is
//! asking: it picks the payload format from the `User-Agent`, and with a HWID device limit
//! enabled it wants `x-hwid` (plus the optional `x-device-os` / `x-ver-os` / `x-device-model`)
//! before it hands out a subscription at all. Fetched without any of that — which is what
//! `reqwest` sends by default, not even a `User-Agent` — a source can answer with the wrong
//! format or refuse outright.
//!
//! The headers are the injector's own, not the client's: nothing from the request that triggered
//! the fetch is forwarded here. That keeps one answer per source (the cache stays keyed on the
//! source URL alone) instead of an answer shaped by whichever device happened to arrive first.

use std::collections::HashMap;

/// The set a source sees by default: one Happ client, on one device.
const DEFAULTS: &[(&str, &str)] = &[
    ("user-agent", "Happ/2.0.0 (com.happproxy; iOS 18.3.0)"),
    ("accept", "*/*"),
    ("x-device-os", "iOS"),
    ("x-ver-os", "18.3"),
    ("x-device-model", "iPhone"),
];

/// Remnawave documents `x-hwid` as at most this long.
pub const MAX_HWID_LEN: usize = 36;

/// Headers the injector may not be told to set, because it sets them itself or because setting
/// them breaks the fetch:
///
/// - the two conditional validators are the cache's own, written per request in
///   [`crate::cache::LinksCache::refresh_url`];
/// - a hand-set `accept-encoding` turns off reqwest's automatic decompression, so the body would
///   arrive still gzipped and parse as no links at all;
/// - `host` and `content-length` belong to the transport, and the rest are hop-by-hop.
const RESERVED: &[&str] = &[
    "if-none-match", "if-modified-since", "accept-encoding", "host", "content-length",
    "connection", "keep-alive", "transfer-encoding", "upgrade", "trailer", "te",
];

pub fn is_reserved(name: &str) -> bool {
    RESERVED.contains(&name.to_lowercase().as_str())
}

/// What the injector sends when it fetches a links source over HTTP.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceHeaders {
    /// Names are lowercase, and the order is stable so a log reads the same on every start.
    headers: Vec<(String, String)>,
}

impl SourceHeaders {
    /// The Happ-shaped defaults, with an `x-hwid` derived from `seed`.
    pub fn happ_defaults(seed: &str) -> Self {
        let mut headers: Vec<(String, String)> = DEFAULTS
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect();
        headers.push(("x-hwid".to_string(), derive_hwid(seed)));
        Self { headers }
    }

    /// The defaults with the config's `[source_headers]` applied on top: a known name is
    /// replaced, an unknown one is appended, and an empty value drops the header entirely.
    pub fn from_config(seed: &str, overrides: &HashMap<String, String>) -> Self {
        let mut headers = Self::happ_defaults(seed).headers;

        // Sorted so the resulting order — and the startup log — does not depend on the hash map.
        let mut pairs: Vec<(String, &String)> = overrides
            .iter()
            .map(|(name, value)| (name.to_lowercase(), value))
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));

        for (name, value) in pairs {
            let at = headers.iter().position(|(existing, _)| *existing == name);
            match (at, value.is_empty()) {
                (Some(at), true) => {
                    headers.remove(at);
                }
                (Some(at), false) => headers[at].1 = value.clone(),
                (None, true) => {}
                (None, false) => headers.push((name, value.clone())),
            }
        }

        Self { headers }
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Header names only — `x-hwid` identifies this deployment to the source, so the values stay
    /// out of the log the same way a source's token does.
    pub fn names(&self) -> Vec<&str> {
        self.headers.iter().map(|(name, _)| name.as_str()).collect()
    }

    pub fn apply(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        self.headers
            .iter()
            .fold(request, |request, (name, value)| request.header(name.as_str(), value.as_str()))
    }
}

/// A stable device id for this deployment, in the shape of a UUID.
///
/// Derived rather than stored: a source counting devices must see the same id after a restart or
/// an upgrade, or every deployment of the same config eats another slot of its device limit.
/// FNV-1a rather than [`std::collections::hash_map::DefaultHasher`] for exactly that reason —
/// SipHash's output is not promised to be stable across Rust releases.
pub fn derive_hwid(seed: &str) -> String {
    let hex = format!("{:016x}{:016x}", fnv1a(seed.as_bytes(), FNV_OFFSET), fnv1a(seed.as_bytes(), FNV_OFFSET ^ 0x5555_5555_5555_5555));
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a(bytes: &[u8], offset: u64) -> u64 {
    bytes.iter().fold(offset, |hash, byte| (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overrides(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(n, v)| ((*n).to_string(), (*v).to_string())).collect()
    }

    fn value<'a>(headers: &'a SourceHeaders, name: &str) -> Option<&'a str> {
        headers.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    #[test]
    fn defaults_look_like_a_happ_client() {
        let headers = SourceHeaders::happ_defaults("http://upstream:2096");
        assert!(value(&headers, "user-agent").unwrap().to_lowercase().contains("happ"));
        assert_eq!(value(&headers, "x-device-os"), Some("iOS"));
        assert!(value(&headers, "x-hwid").is_some());
    }

    #[test]
    fn hwid_is_stable_for_a_seed_and_differs_between_seeds() {
        assert_eq!(derive_hwid("http://upstream:2096"), derive_hwid("http://upstream:2096"));
        assert_ne!(derive_hwid("http://upstream:2096"), derive_hwid("http://other:2096"));
    }

    #[test]
    fn hwid_has_the_shape_and_length_of_a_uuid() {
        let hwid = derive_hwid("http://upstream:2096");
        assert_eq!(hwid.len(), MAX_HWID_LEN);
        let groups: Vec<usize> = hwid.split('-').map(str::len).collect();
        assert_eq!(groups, vec![8, 4, 4, 4, 12]);
        assert!(hwid.chars().all(|c| c.is_ascii_hexdigit() || c == '-'), "{hwid}");
    }

    #[test]
    fn config_replaces_a_default() {
        let headers = SourceHeaders::from_config("seed", &overrides(&[("User-Agent", "Happ/9.9.9")]));
        assert_eq!(value(&headers, "user-agent"), Some("Happ/9.9.9"), "the name is matched case-insensitively");
        assert_eq!(headers.names().iter().filter(|n| **n == "user-agent").count(), 1);
    }

    #[test]
    fn config_adds_an_unknown_header() {
        let headers = SourceHeaders::from_config("seed", &overrides(&[("x-custom", "1")]));
        assert_eq!(value(&headers, "x-custom"), Some("1"));
    }

    #[test]
    fn an_empty_value_drops_the_header() {
        let headers = SourceHeaders::from_config("seed", &overrides(&[("x-hwid", "")]));
        assert_eq!(value(&headers, "x-hwid"), None);
        assert!(value(&headers, "user-agent").is_some(), "the rest of the set survives");
    }

    #[test]
    fn reserved_names_are_recognised_whatever_their_case() {
        assert!(is_reserved("If-None-Match"));
        assert!(is_reserved("accept-encoding"));
        assert!(!is_reserved("x-hwid"));
    }
}
