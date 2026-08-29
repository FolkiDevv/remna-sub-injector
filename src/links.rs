//! Turning whatever a links source returned into a list of proxy URIs, and reading the refresh
//! interval the source announced.

use std::{fmt, time::Duration};

use axum::http::HeaderMap;

use crate::subscription::{all_entries_are_service_hosts, decode_sub_body, is_proxy_uri};

/// Never refresh a source more often than this, whatever it asks for.
pub const MIN_TTL: Duration = Duration::from_secs(30);
/// Never trust a refresh interval longer than this — a stray `profile-update-interval: 8760`
/// would otherwise freeze the cache for a year.
pub const MAX_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    File,
    Url,
}

pub fn source_kind(source: &str) -> SourceKind {
    if source.starts_with("http://") || source.starts_with("https://") {
        SourceKind::Url
    } else {
        SourceKind::File
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LinksError {
    /// Nothing in the payload looked like a proxy URI, base64 included — an HTML error page,
    /// a captive portal, an empty file.
    NoValidUris,
    /// The source is a subscription whose own account is disabled, expired or out of traffic.
    ServiceMessage,
    /// Some lines are not proxy URIs. Only reported for remote sources.
    InvalidLines { count: usize },
}

impl fmt::Display for LinksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoValidUris => write!(f, "no proxy links in the response"),
            Self::ServiceMessage => write!(f, "source is a service message, not a subscription"),
            Self::InvalidLines { count } => write!(f, "{count} line(s) are not proxy links"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParsedLinks {
    pub links: Vec<String>,
    /// Lines dropped as invalid. Always 0 for a remote source — there any invalid line fails
    /// the whole fetch instead.
    pub skipped: usize,
}

/// Reads a links source payload.
///
/// The payload may be a plain list of proxy URIs, one per line, or a whole base64 subscription
/// (Remnawave, Marzban and friends serve those) — which shape it is gets detected, not configured.
///
/// A local file is a hand-written list, so an unreadable line is treated as a typo: it is dropped
/// and reported through [`ParsedLinks::skipped`]. A remote payload is machine-generated, so a line
/// that is not a proxy URI means the response is corrupt (a truncated body, an error page) and the
/// whole source is rejected.
pub fn parse_links_payload(raw: &str, kind: SourceKind) -> Result<ParsedLinks, LinksError> {
    let (links, skipped) = match split_uris(raw) {
        // Nothing readable as-is — the payload is probably a base64 subscription.
        (links, _) if links.is_empty() => {
            let decoded = decode_sub_body(raw.as_bytes()).ok_or(LinksError::NoValidUris)?;
            let (links, skipped) = split_uris(&decoded);
            if links.is_empty() {
                return Err(LinksError::NoValidUris);
            }
            (links, skipped)
        }
        found => found,
    };

    if all_entries_are_service_hosts(&links.join("\n")) {
        return Err(LinksError::ServiceMessage);
    }
    if skipped > 0 && kind == SourceKind::Url {
        return Err(LinksError::InvalidLines { count: skipped });
    }
    Ok(ParsedLinks { links, skipped })
}

fn split_uris(text: &str) -> (Vec<String>, usize) {
    let mut links = Vec::new();
    let mut skipped = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if is_proxy_uri(line) {
            links.push(line.to_string());
        } else {
            skipped += 1;
        }
    }
    (links, skipped)
}

/// How long a source's answer may be reused.
#[derive(Debug, Clone, Copy)]
pub struct TtlPolicy {
    /// Used when the source announces nothing.
    pub default: Duration,
    pub min: Duration,
    pub max: Duration,
    /// `false` ignores what the source announces and always uses `default`.
    pub respect_headers: bool,
}

impl TtlPolicy {
    pub fn new(default: Duration, respect_headers: bool) -> Self {
        Self { default, min: MIN_TTL, max: MAX_TTL, respect_headers }
    }

    /// How long the source's answer may be reused.
    ///
    /// Subscription panels announce their refresh interval through `profile-update-interval`, in
    /// **hours**, per the XTLS subscription standard — that is the signal clients themselves
    /// follow, and Remnawave, Marzban, Marzneshin and Hiddify all send it. `Cache-Control` is not
    /// part of that standard and only shows up when a plain-text list is served as a static file
    /// by nginx or a CDN, so it is the second choice. Failing both, the configured default is used.
    ///
    /// The result is always clamped to `[min, max]`.
    pub fn for_headers(&self, headers: &HeaderMap) -> Duration {
        let announced = if self.respect_headers {
            profile_update_interval(headers).or_else(|| cache_control_ttl(headers, self.min))
        } else {
            None
        };
        announced.unwrap_or(self.default).clamp(self.min, self.max)
    }
}

fn profile_update_interval(headers: &HeaderMap) -> Option<Duration> {
    let hours: u64 = header_str(headers, "profile-update-interval")?.trim().parse().ok()?;
    // 0 would mean "refresh constantly"; the clamp turns it into MIN_TTL either way, but there is
    // no reason to treat it as an announced interval at all.
    (hours > 0).then(|| Duration::from_secs(hours.saturating_mul(3600)))
}

fn cache_control_ttl(headers: &HeaderMap, min_ttl: Duration) -> Option<Duration> {
    let value = header_str(headers, "cache-control")?.to_lowercase();
    let mut max_age = None;
    let mut s_maxage = None;
    let mut no_cache = false;
    for directive in value.split(',') {
        let directive = directive.trim();
        match directive.split_once('=') {
            // A shared cache is what this is, so s-maxage wins over max-age.
            Some(("max-age", secs)) => max_age = secs.trim().parse::<u64>().ok(),
            Some(("s-maxage", secs)) => s_maxage = secs.trim().parse::<u64>().ok(),
            _ if directive == "no-cache" || directive == "no-store" => no_cache = true,
            _ => {}
        }
    }
    // "do not cache" still gets MIN_TTL rather than 0: refetching on every client request would
    // hammer the source for no benefit.
    if no_cache {
        return Some(min_ttl);
    }
    s_maxage.or(max_age).map(Duration::from_secs)
}

pub fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// A source as it may appear in a log.
///
/// A source can be a real subscription URL, and its path is the secret that guards it, so only
/// the scheme and host survive. File paths are printed whole — they are not secrets, and the
/// operator needs to know which file went bad.
pub fn source_label(source: &str) -> String {
    let Some((scheme, rest)) = source.split_once("://") else {
        return source.to_string();
    };
    if source_kind(source) == SourceKind::File {
        return source.to_string();
    }
    let rest = rest.split(['?', '#']).next().unwrap_or("");
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, path),
        None => (rest, ""),
    };
    // Credentials in the authority are a secret too.
    let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    if path.is_empty() {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}/...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    const LINKS: &str = "vless://aaaaa@1.2.3.4:443#node1\nss://bbbbbb@5.6.7.8:8388#node2";
    const SERVICE_LINKS: &str = "vless://uuid@0.0.0.0:1?encryption=none#%F0%9F%9A%A8%20Subscription%20expired\nvless://uuid@0.0.0.0:1#Contact%20support";

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        use axum::http::HeaderName;
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(HeaderName::from_bytes(name.as_bytes()).unwrap(), value.parse().unwrap());
        }
        map
    }

    #[test]
    fn plain_text_list_is_parsed() {
        let parsed = parse_links_payload(LINKS, SourceKind::Url).unwrap();
        assert_eq!(parsed.links.len(), 2);
        assert_eq!(parsed.skipped, 0);
        assert!(parsed.links[0].starts_with("vless://"));
    }

    #[test]
    fn blank_lines_and_padding_are_ignored() {
        let raw = "\n  vless://aaaaa@1.2.3.4:443#node1  \n\n\tss://bbbbbb@5.6.7.8:8388#node2\n\n";
        let parsed = parse_links_payload(raw, SourceKind::Url).unwrap();
        assert_eq!(parsed.links, vec!["vless://aaaaa@1.2.3.4:443#node1", "ss://bbbbbb@5.6.7.8:8388#node2"]);
    }

    #[test]
    fn base64_subscription_is_decoded() {
        let body = STANDARD.encode(LINKS.as_bytes());
        let parsed = parse_links_payload(&body, SourceKind::Url).unwrap();
        assert_eq!(parsed.links.len(), 2, "a real subscription body should be decoded, not injected raw");
    }

    #[test]
    fn base64_subscription_wrapped_at_76_chars_is_decoded() {
        let raw = STANDARD.encode(LINKS.as_bytes());
        let wrapped = raw.as_bytes().chunks(76)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let parsed = parse_links_payload(&wrapped, SourceKind::Url).unwrap();
        assert_eq!(parsed.links.len(), 2);
    }

    #[test]
    fn html_error_page_is_rejected() {
        let page = "<!DOCTYPE html>\n<html><body>502 Bad Gateway</body></html>";
        assert_eq!(parse_links_payload(page, SourceKind::Url), Err(LinksError::NoValidUris));
        assert_eq!(parse_links_payload(page, SourceKind::File), Err(LinksError::NoValidUris));
    }

    #[test]
    fn empty_payload_is_rejected() {
        assert_eq!(parse_links_payload("", SourceKind::File), Err(LinksError::NoValidUris));
        assert_eq!(parse_links_payload("   \n\n", SourceKind::File), Err(LinksError::NoValidUris));
    }

    #[test]
    fn service_message_source_is_rejected() {
        // A source subscription whose own account expired: injecting its stubs would hand
        // clients dead nodes.
        assert_eq!(parse_links_payload(SERVICE_LINKS, SourceKind::Url), Err(LinksError::ServiceMessage));
        let encoded = STANDARD.encode(SERVICE_LINKS.as_bytes());
        assert_eq!(parse_links_payload(&encoded, SourceKind::Url), Err(LinksError::ServiceMessage));
    }

    #[test]
    fn file_drops_invalid_lines_and_reports_them() {
        let raw = "vless://aaaaa@1.2.3.4:443#node1\noops-a-typo\nss://bbbbbb@5.6.7.8:8388#node2";
        let parsed = parse_links_payload(raw, SourceKind::File).unwrap();
        assert_eq!(parsed.links.len(), 2);
        assert_eq!(parsed.skipped, 1);
    }

    #[test]
    fn url_with_one_invalid_line_is_rejected_whole() {
        let raw = "vless://aaaaa@1.2.3.4:443#node1\noops-a-typo\nss://bbbbbb@5.6.7.8:8388#node2";
        assert_eq!(
            parse_links_payload(raw, SourceKind::Url),
            Err(LinksError::InvalidLines { count: 1 })
        );
    }

    #[test]
    fn partially_valid_text_is_not_treated_as_base64() {
        // Only a payload with no readable URI at all is retried as base64.
        let raw = "vless://aaaaa@1.2.3.4:443#node1\nZm9vYmFy";
        let parsed = parse_links_payload(raw, SourceKind::File).unwrap();
        assert_eq!(parsed.links, vec!["vless://aaaaa@1.2.3.4:443#node1"]);
        assert_eq!(parsed.skipped, 1);
    }

    // ── refresh interval ───────────────────────────────────────────────────────

    fn policy() -> TtlPolicy {
        TtlPolicy::new(Duration::from_secs(300), true)
    }

    #[test]
    fn profile_update_interval_is_read_as_hours() {
        let ttl = policy().for_headers(&headers(&[("profile-update-interval", "12")]));
        assert_eq!(ttl, Duration::from_secs(12 * 3600), "Remnawave's default of 12 means 12 hours");
    }

    #[test]
    fn profile_update_interval_wins_over_cache_control() {
        let ttl = policy().for_headers(&headers(&[
            ("profile-update-interval", "2"),
            ("cache-control", "max-age=60"),
        ]));
        assert_eq!(ttl, Duration::from_secs(2 * 3600));
    }

    #[test]
    fn garbage_profile_update_interval_falls_through() {
        for value in ["abc", "", "-1", "0", "1.5"] {
            let ttl = policy().for_headers(&headers(&[("profile-update-interval", value)]));
            assert_eq!(ttl, policy().default, "value {value:?} should be ignored");
        }
    }

    #[test]
    fn cache_control_is_used_when_no_subscription_header() {
        assert_eq!(
            policy().for_headers(&headers(&[("cache-control", "public, max-age=600")])),
            Duration::from_secs(600)
        );
        // A shared cache follows s-maxage over max-age.
        assert_eq!(
            policy().for_headers(&headers(&[("cache-control", "max-age=600, s-maxage=90")])),
            Duration::from_secs(90)
        );
        // "Do not cache" still means the minimum, not "refetch on every client request".
        assert_eq!(policy().for_headers(&headers(&[("cache-control", "no-store")])), MIN_TTL);
        assert_eq!(policy().for_headers(&headers(&[("cache-control", "no-cache")])), MIN_TTL);
    }

    #[test]
    fn config_default_is_used_without_headers() {
        assert_eq!(policy().for_headers(&HeaderMap::new()), policy().default);
    }

    #[test]
    fn headers_are_ignored_when_disabled() {
        let policy = TtlPolicy::new(Duration::from_secs(300), false);
        let map = headers(&[("profile-update-interval", "12"), ("cache-control", "max-age=60")]);
        assert_eq!(policy.for_headers(&map), policy.default);
    }

    #[test]
    fn ttl_is_clamped_at_both_ends() {
        assert_eq!(policy().for_headers(&headers(&[("cache-control", "max-age=1")])), MIN_TTL);
        assert_eq!(policy().for_headers(&headers(&[("profile-update-interval", "8760")])), MAX_TTL);
    }

    // ── log redaction ──────────────────────────────────────────────────────────

    #[test]
    fn source_label_hides_the_subscription_token() {
        let label = source_label("https://panel.example.com/sub/SECRET-TOKEN");
        assert!(!label.contains("SECRET-TOKEN"), "token must never reach the log: {label}");
        assert!(label.contains("panel.example.com"), "host is what makes the log useful: {label}");
        assert_eq!(source_label("https://panel.example.com/SECRET"), "https://panel.example.com/...");
        assert_eq!(source_label("https://panel.example.com"), "https://panel.example.com");
        assert_eq!(
            source_label("https://user:pass@panel.example.com/sub/T?k=v"),
            "https://panel.example.com/...",
            "credentials are a secret too"
        );
    }

    #[test]
    fn source_label_keeps_file_paths_whole() {
        assert_eq!(source_label("/data/hysteria2-links.txt"), "/data/hysteria2-links.txt");
    }

    #[test]
    fn source_kind_splits_urls_from_paths() {
        assert_eq!(source_kind("https://example.com/list.txt"), SourceKind::Url);
        assert_eq!(source_kind("http://example.com/list.txt"), SourceKind::Url);
        assert_eq!(source_kind("/data/links.txt"), SourceKind::File);
        assert_eq!(source_kind("data/links.txt"), SourceKind::File);
    }
}
