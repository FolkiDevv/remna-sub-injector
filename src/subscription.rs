//! Parsing of subscription bodies: the base64 envelope, the proxy URIs inside it, and the
//! signals Remnawave uses to mark a subscription as not serviceable.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};

/// Decodes a base64 subscription body.
///
/// Some upstreams wrap the payload at 76 characters, so whitespace is stripped first. Both the
/// standard and the URL-safe alphabet are accepted — panels differ — but re-encoding always uses
/// the standard one, so what clients receive keeps the shape they already got.
pub fn decode_sub_body(body: &[u8]) -> Option<String> {
    let stripped: Vec<u8> = body.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    let decoded = STANDARD
        .decode(&stripped)
        .or_else(|_| URL_SAFE_NO_PAD.decode(trim_padding(&stripped)))
        .ok()?;
    String::from_utf8(decoded).ok()
}

/// `URL_SAFE_NO_PAD` rejects trailing `=`, which a padded URL-safe body still carries.
fn trim_padding(input: &[u8]) -> &[u8] {
    let end = input.iter().rposition(|b| *b != b'=').map_or(0, |i| i + 1);
    &input[..end]
}

pub fn encode_sub_body(text: &str) -> Vec<u8> {
    STANDARD.encode(text.as_bytes()).into_bytes()
}

/// Appends the extra links to an already decoded subscription list.
pub fn append_links(text: &str, extra: &str) -> String {
    format!("{}\n{}", text.trim(), extra)
}

pub fn inject_links(body: &[u8], extra: &str) -> Vec<u8> {
    match decode_sub_body(body) {
        Some(text) => encode_sub_body(&append_links(&text, extra)),
        None => body.to_vec(),
    }
}

/// Whether a line looks like a proxy URI: `scheme://rest`.
///
/// Deliberately not a list of known schemes — `tuic://`, `anytls://` and whatever comes next must
/// pass without a code change. It only has to separate real entries from an HTML error page, a
/// base64 blob or a stray comment.
pub fn is_proxy_uri(line: &str) -> bool {
    let Some((scheme, rest)) = line.split_once("://") else {
        return false;
    };
    let mut chars = scheme.chars();
    let starts_ok = chars.next().is_some_and(|c| c.is_ascii_alphabetic());
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
    starts_ok && rest_ok && !rest.is_empty()
}

/// Endpoints Remnawave uses for its placeholder entries — never a reachable node.
const SERVICE_HOSTS: &[&str] = &["0.0.0.0", "127.0.0.1", "::", "::1", "localhost"];

pub fn is_service_host(host: &str) -> bool {
    SERVICE_HOSTS.iter().any(|h| host.eq_ignore_ascii_case(h))
}

/// Extracts the host from a proxy URI (`scheme://userinfo@host:port/path?query#fragment`).
/// Returns `None` when the endpoint is not in plain sight — `vmess://` hides it inside a
/// base64 payload, and legacy `ss://` links encode the whole authority.
pub fn proxy_uri_host(line: &str) -> Option<&str> {
    let (scheme, rest) = line.split_once("://")?;
    if scheme.trim().is_empty() || scheme.trim().eq_ignore_ascii_case("vmess") {
        return None;
    }
    // Cut query and fragment first: both may carry '@' and ':' of their own.
    let rest = rest.split(['?', '#']).next().unwrap_or("");
    // Userinfo can itself contain '@' (base64 payloads), so the last one wins.
    let authority = match rest.rsplit_once('@') {
        Some((_, host)) => host,
        None => rest,
    };
    let authority = authority.split('/').next().unwrap_or("");
    let host = if authority.starts_with('[') {
        // Bracketed IPv6: [::1]:443
        authority.get(1..authority.find(']')?)?
    } else {
        match authority.rsplit_once(':') {
            // A bare IPv6 has several colons — it carries no port, keep it whole.
            Some((h, _)) if !h.contains(':') => h,
            _ => authority,
        }
    };
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Remnawave answers a disabled, expired or traffic-limited user with placeholder entries
/// that all point at a non-routable endpoint (`0.0.0.0:1`) and carry the status as their
/// remark. A real subscription never consists solely of such entries.
///
/// Deliberately conservative: an entry whose host cannot be read counts as real, so an
/// unusual body is injected rather than silently skipped.
pub fn all_entries_are_service_hosts(text: &str) -> bool {
    let mut saw_entry = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        saw_entry = true;
        match proxy_uri_host(line) {
            Some(host) if is_service_host(host) => {}
            _ => return false,
        }
    }
    saw_entry
}

/// Fields of the `subscription-userinfo` response header (XTLS/Marzban subscription standard).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SubscriptionUserinfo {
    pub upload: Option<u64>,
    pub download: Option<u64>,
    pub total: Option<u64>,
    pub expire: Option<u64>,
}

/// Parses `upload=0; download=172266402; total=0; expire=1771177005`.
/// Unknown keys and unparsable values are ignored.
pub fn parse_subscription_userinfo(value: &str) -> SubscriptionUserinfo {
    let mut info = SubscriptionUserinfo::default();
    for part in value.split(';') {
        let Some((key, val)) = part.split_once('=') else {
            continue;
        };
        let Ok(num) = val.trim().parse::<u64>() else {
            continue;
        };
        match key.trim().to_lowercase().as_str() {
            "upload" => info.upload = Some(num),
            "download" => info.download = Some(num),
            "total" => info.total = Some(num),
            "expire" => info.expire = Some(num),
            _ => {}
        }
    }
    info
}

/// Why the subscription is not serviceable, if it isn't — used both to gate injection and
/// to explain the skip in the log.
///
/// `expire = 0` means "never expires" and `total = 0` means "unlimited traffic"; neither is
/// a service state, so both are only checked when non-zero.
pub fn userinfo_service_reason(info: &SubscriptionUserinfo, now_unix: u64) -> Option<&'static str> {
    if let Some(expire) = info.expire {
        // Some panels report the timestamp in milliseconds.
        let expire = if expire > 1_000_000_000_000 { expire / 1000 } else { expire };
        if expire > 0 && expire <= now_unix {
            return Some("expired");
        }
    }
    if let Some(total) = info.total {
        let used = info.upload.unwrap_or(0).saturating_add(info.download.unwrap_or(0));
        if total > 0 && used >= total {
            return Some("traffic limit");
        }
    }
    None
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_LINKS: &str = "vless://aaaaa@1.2.3.4:443#node1\nss://bbbbbb@5.6.7.8:8388#node2";
    /// Real body Remnawave returns for an expired subscription: placeholder entries on
    /// 0.0.0.0:1 with the status as a percent-encoded remark.
    const SERVICE_LINKS: &str = "vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?encryption=none&packetEncoding=xudp#%F0%9F%9A%A8%20Subscription%20expired\nvless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?encryption=none&packetEncoding=xudp#Contact%20support";
    /// The header that came with it. expire = 2026-02-15, total = 0 means unlimited traffic.
    const EXPIRED_USERINFO: &str = "upload=0; download=172266402; total=0; expire=1771177005";
    const EXTRA_LINKS: &str = "hysteria2://PASS@10.0.0.1:5350?obfs=salamander&obfs-password=OBFS#node-fi\nhysteria2://PASS@10.0.0.2:5350?obfs=salamander&obfs-password=OBFS#node-pl";

    fn decode_b64(s: &str) -> String {
        let stripped: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        STANDARD
            .decode(&stripped)
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default()
    }

    #[test]
    fn inject_links_roundtrip() {
        let body = STANDARD.encode(FAKE_LINKS.as_bytes()).into_bytes();
        let result = inject_links(&body, EXTRA_LINKS);
        let decoded = decode_b64(&String::from_utf8(result).unwrap());
        assert!(decoded.contains("vless://aaaaa"), "original links preserved");
        assert!(decoded.contains("hysteria2://"), "hysteria2 injected");
        assert!(decoded.contains("node-fi"), "first extra link present");
        assert!(decoded.contains("node-pl"), "second extra link present");
    }

    #[test]
    fn inject_links_invalid_b64_passthrough() {
        let body = b"not-base64!!";
        let result = inject_links(body, EXTRA_LINKS);
        assert_eq!(result, body, "invalid b64 should pass through unchanged");
    }

    #[test]
    fn inject_links_wrapped_base64() {
        // Некоторые upstream оборачивают base64 по 76 символов
        let raw = STANDARD.encode(FAKE_LINKS.as_bytes());
        let wrapped = raw.as_bytes().chunks(76)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let result = inject_links(wrapped.as_bytes(), EXTRA_LINKS);
        let decoded = decode_b64(&String::from_utf8(result).unwrap());
        assert!(decoded.contains("vless://aaaaa"), "original links preserved after unwrap");
        assert!(decoded.contains("hysteria2://"), "extra links injected after unwrap");
    }

    #[test]
    fn decode_sub_body_accepts_url_safe_alphabet() {
        // '+' and '/' become '-' and '_' — some panels serve subscriptions this way.
        let body = "vless://uuid@1.2.3.4:443?flow=xtls-rprx-vision&x=a~b#node?>";
        let url_safe = base64::engine::general_purpose::URL_SAFE.encode(body.as_bytes());
        let standard = STANDARD.encode(body.as_bytes());
        assert_ne!(url_safe, standard, "fixture must actually differ between alphabets");
        assert_eq!(decode_sub_body(url_safe.as_bytes()).as_deref(), Some(body));
    }

    #[test]
    fn is_proxy_uri_accepts_real_links_and_rejects_junk() {
        for line in [
            "vless://uuid@1.2.3.4:443#node",
            "hysteria2://PASS@10.0.0.1:5350?obfs=salamander#node-fi",
            "vmess://eyJhZGQiOiIxLjIuMy40In0=",
            "ss://YWVzOnBhc3M@5.6.7.8:8388#node",
            "tuic://uuid:pass@example.com:443#future-scheme",
        ] {
            assert!(is_proxy_uri(line), "{line} should be a proxy URI");
        }
        for line in [
            "<!DOCTYPE html>",
            "# a comment",
            "not-a-uri",
            "://no-scheme",
            "1vless://digit-first@1.2.3.4:443",
            "vless://",
            "dGhpcyBpcyBiYXNlNjQ=",
            "",
        ] {
            assert!(!is_proxy_uri(line), "{line} should NOT be a proxy URI");
        }
    }

    // ── service-message detection ──────────────────────────────────────────────

    #[test]
    fn proxy_uri_host_extracts_host() {
        let cases = [
            ("vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?encryption=none&packetEncoding=xudp#%F0%9F%9A%A8%20Subscription%20expired", Some("0.0.0.0")),
            ("vless://uuid@node.example.com:443?security=tls#My-Node", Some("node.example.com")),
            ("hysteria2://PASS@10.0.0.1:5350?obfs=salamander#node-fi", Some("10.0.0.1")),
            ("ss://bbbbbb@5.6.7.8:8388#node2", Some("5.6.7.8")),
            ("vless://uuid@[::1]:443#ipv6-node", Some("::1")),
            ("trojan://pass@localhost:1#stub", Some("localhost")),
            ("vless://uuid@example.com#no-port", Some("example.com")),
            // vmess hides the endpoint inside a base64 payload
            ("vmess://eyJhZGQiOiIxLjIuMy40In0=", None),
            ("not-a-uri", None),
            ("", None),
        ];
        for (line, expected) in cases {
            assert_eq!(proxy_uri_host(line), expected, "line: {line}");
        }
    }

    #[test]
    fn is_service_host_matches_placeholders() {
        for host in &["0.0.0.0", "127.0.0.1", "::", "::1", "localhost", "LocalHost"] {
            assert!(is_service_host(host), "{host} should be a service host");
        }
        for host in &["1.2.3.4", "node.example.com", "10.0.0.1", ""] {
            assert!(!is_service_host(host), "{host} should NOT be a service host");
        }
    }

    #[test]
    fn service_body_detected_by_hosts() {
        assert!(all_entries_are_service_hosts(SERVICE_LINKS), "reference stub body");
    }

    #[test]
    fn real_body_not_detected_as_service() {
        assert!(!all_entries_are_service_hosts(FAKE_LINKS));
        assert!(!all_entries_are_service_hosts(EXTRA_LINKS));
    }

    #[test]
    fn mixed_body_not_detected_as_service() {
        // One real node among stubs means the subscription still works.
        let mixed = format!("{SERVICE_LINKS}\nvless://aaaaa@1.2.3.4:443#node1");
        assert!(!all_entries_are_service_hosts(&mixed));
    }

    #[test]
    fn empty_body_not_detected_as_service() {
        assert!(!all_entries_are_service_hosts(""));
        assert!(!all_entries_are_service_hosts("\n  \n"));
    }

    #[test]
    fn parse_userinfo_reference_header() {
        assert_eq!(
            parse_subscription_userinfo(EXPIRED_USERINFO),
            SubscriptionUserinfo {
                upload: Some(0),
                download: Some(172266402),
                total: Some(0),
                expire: Some(1771177005),
            }
        );
    }

    #[test]
    fn parse_userinfo_partial_and_garbage() {
        // Missing fields stay None, unknown keys and unparsable values are ignored.
        assert_eq!(
            parse_subscription_userinfo("total=100;expire=abc;foo=1;bare"),
            SubscriptionUserinfo { total: Some(100), ..Default::default() }
        );
        assert_eq!(parse_subscription_userinfo(""), SubscriptionUserinfo::default());
        assert_eq!(parse_subscription_userinfo("nonsense"), SubscriptionUserinfo::default());
        // Padding around keys and values is tolerated.
        assert_eq!(
            parse_subscription_userinfo("  UPLOAD = 5 ;  download=7  "),
            SubscriptionUserinfo { upload: Some(5), download: Some(7), ..Default::default() }
        );
    }

    #[test]
    fn userinfo_reason_expiry() {
        let now = 2_000_000_000;
        let at = |expire| SubscriptionUserinfo { expire: Some(expire), ..Default::default() };

        assert_eq!(userinfo_service_reason(&at(now - 1), now), Some("expired"));
        assert_eq!(userinfo_service_reason(&at(now), now), Some("expired"));
        assert_eq!(userinfo_service_reason(&at(now + 1), now), None);
        // 0 means "never expires", not "expired at the epoch"
        assert_eq!(userinfo_service_reason(&at(0), now), None);
        // milliseconds are normalised to seconds
        assert_eq!(userinfo_service_reason(&at((now - 1) * 1000), now), Some("expired"));
        assert_eq!(userinfo_service_reason(&at((now + 1000) * 1000), now), None);
        assert_eq!(userinfo_service_reason(&SubscriptionUserinfo::default(), now), None);
    }

    #[test]
    fn userinfo_reason_traffic() {
        let now = 2_000_000_000;
        let used = |upload, download, total| SubscriptionUserinfo {
            upload: Some(upload), download: Some(download), total: Some(total), expire: None,
        };

        assert_eq!(userinfo_service_reason(&used(40, 60, 100), now), Some("traffic limit"));
        assert_eq!(userinfo_service_reason(&used(60, 60, 100), now), Some("traffic limit"));
        assert_eq!(userinfo_service_reason(&used(10, 10, 100), now), None);
        // total = 0 is unlimited traffic — the case in the reference header
        assert_eq!(userinfo_service_reason(&used(0, 172266402, 0), now), None);
    }

    #[test]
    fn userinfo_reason_reference_header_is_expired() {
        let info = parse_subscription_userinfo(EXPIRED_USERINFO);
        // Any clock after 2026-02-15 sees this subscription as expired.
        assert_eq!(userinfo_service_reason(&info, 1_771_177_006), Some("expired"));
        assert_eq!(userinfo_service_reason(&info, 1_771_177_004), None);
    }
}
