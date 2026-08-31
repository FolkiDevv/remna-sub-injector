//! The reverse proxy itself: forward the request, decide whether the response may be extended,
//! and append the configured extra links when it may.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
    routing::get,
    Router,
};

use crate::{
    cache::LinksCache,
    config::InjectionRule,
    links::source_label,
    subscription::{
        all_entries_are_service_hosts, append_links, decode_sub_body, encode_sub_body, now_unix,
        parse_subscription_userinfo, userinfo_service_reason,
    },
    MAX_BODY_SIZE,
};

pub struct AppState {
    pub upstream: String,
    pub bind_addr: String,
    pub injections: Vec<InjectionRule>,
    pub client: reqwest::Client,
    pub links_cache: LinksCache,
}

pub fn find_matching_rule<'a>(headers: &HeaderMap, rules: &'a [InjectionRule]) -> Option<&'a InjectionRule> {
    for rule in rules {
        let header_name = rule.header.to_lowercase();
        let header_val = headers
            .get(header_name.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        if rule.contains.iter().any(|pat| header_val.contains(pat.as_str())) {
            return Some(rule);
        }
    }
    None
}

pub async fn proxy(
    State(cfg): State<Arc<AppState>>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response<axum::body::Body>, StatusCode> {
    let upstream_url = format!(
        "{}{}",
        cfg.upstream,
        uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/")
    );

    // Everything logged about the request is redacted: the path carries the subscription token.
    let path = path_preview(uri.path());
    let ua_preview = headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("").chars().take(40).collect::<String>();
    eprintln!("[sub-injector] >> GET {} ua={ua_preview:?}", path_preview(uri.path()));

    // `connection` is hop-by-hop. `accept-encoding` belongs to reqwest: it advertises the
    // compressions it can actually decode, while a client's list may name one it cannot (zstd,
    // say). Forwarded, that list makes the panel answer in a compression the injector cannot
    // read, and the body reaches `decode_sub_body` still encoded — where it reads as "not a
    // subscription" and injection silently does nothing.
    const SKIP_REQUEST: &[&str] = &["connection", "accept-encoding"];

    let mut req = cfg.client.get(&upstream_url);

    for (name, value) in &headers {
        if SKIP_REQUEST.contains(&name.as_str().to_lowercase().as_str()) {
            continue;
        }
        req = req.header(name.as_str(), value.to_str().unwrap_or(""));
    }

    let resp = req.send().await.map_err(|e| {
        eprintln!("[sub-injector] send error for {path}: {e}");
        StatusCode::BAD_GATEWAY
    })?;
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let content_type = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if resp.content_length().unwrap_or(0) > MAX_BODY_SIZE {
        eprintln!("[sub-injector] upstream body too large for {path}");
        return Err(StatusCode::BAD_GATEWAY);
    }

    let body_bytes = resp.bytes().await.map_err(|e| {
        eprintln!("[sub-injector] body error for {path}: {e}");
        StatusCode::BAD_GATEWAY
    })?;

    if body_bytes.len() as u64 > MAX_BODY_SIZE {
        eprintln!("[sub-injector] upstream body too large for {path}");
        return Err(StatusCode::BAD_GATEWAY);
    }

    let is_yaml_or_json = content_type.contains("yaml") || content_type.contains("json");
    let matched_rule = find_matching_rule(&headers, &cfg.injections);
    eprintln!(
        "[sub-injector] matched_rule={} ct={content_type:?} body_len={}",
        matched_rule.map_or("none".to_string(), rule_label),
        body_bytes.len()
    );

    // Remnawave serves a disabled, expired or traffic-limited user an informational stub
    // instead of a real subscription. Appending extra hosts to one would hand a blocked
    // user working nodes, so those responses are proxied untouched.
    let userinfo_reason = resp_headers
        .get("subscription-userinfo")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| userinfo_service_reason(&parse_subscription_userinfo(v), now_unix()));

    let final_body: Bytes = match matched_rule {
        Some(rule) if !is_yaml_or_json => {
            if let Some(reason) = userinfo_reason {
                eprintln!("[sub-injector] skipping injection: service message (userinfo: {reason})");
                body_bytes
            } else {
                match decode_sub_body(&body_bytes) {
                    Some(text) if all_entries_are_service_hosts(&text) => {
                        eprintln!("[sub-injector] skipping injection: service message (service hosts)");
                        body_bytes
                    }
                    Some(text) => {
                        let extra = cfg.links_cache.collect(&rule.links_source, &cfg.client).await;
                        eprintln!("[sub-injector] extra_links={}", extra.len());
                        if extra.is_empty() {
                            body_bytes
                        } else {
                            let injected = encode_sub_body(&append_links(&text, &extra.join("\n")));
                            eprintln!("[sub-injector] injected body_len={}", injected.len());
                            injected.into()
                        }
                    }
                    // Not base64 — nothing this injector knows how to extend.
                    None => body_bytes,
                }
            }
        }
        _ => body_bytes,
    };

    // Hop-by-hop headers that must not be forwarded; also skip content-length
    // since reqwest decompresses the body (making the original length wrong)
    const SKIP: &[&str] = &[
        "connection", "transfer-encoding", "trailer",
        "upgrade", "keep-alive", "content-length",
    ];

    let mut response = Response::builder().status(status.as_u16());
    for (name, value) in &resp_headers {
        if SKIP.contains(&name.as_str()) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            response = response.header(name.as_str(), v);
        }
    }

    response
        .body(axum::body::Body::from(final_body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// A request path as it may appear in a log.
///
/// Only the first segment survives: in the usual `/sub/<token>` shape everything after it is the
/// subscription token, which is the one secret guarding the subscription.
fn path_preview(path: &str) -> String {
    match path.split('/').nth(1).unwrap_or("") {
        "" => "/".to_string(),
        segment => format!("/{segment}/..."),
    }
}

/// A rule's sources as they may appear in a log — a source can be a subscription URL whose path
/// is a secret, so [`source_label`] does the redacting.
fn rule_label(rule: &InjectionRule) -> String {
    rule.links_source.iter().map(|s| source_label(s)).collect::<Vec<_>>().join(", ")
}

pub fn build_app(cfg: Arc<AppState>) -> Router {
    Router::new()
        .route("/{*path}", get(proxy))
        .route("/", get(proxy))
        .with_state(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hy2_rules() -> Vec<InjectionRule> {
        vec![InjectionRule {
            header: "User-Agent".to_string(),
            contains: vec![
                "happ".to_string(), "hiddify".to_string(), "nekobox".to_string(),
                "nekoray".to_string(), "sing-box".to_string(), "clash.meta".to_string(),
                "mihomo".to_string(), "v2rayng".to_string(),
            ],
            links_source: vec!["/tmp/fake.txt".to_string()],
        }]
    }

    #[test]
    fn ua_matching_compatible() {
        let rules = hy2_rules();
        let mut headers = HeaderMap::new();
        for ua in &["happ/2.0", "Hiddify/1.5", "NekoBox/3.0", "sing-box/1.0",
                    "clash.meta/1.18", "Mihomo/1.0", "v2rayng/1.8", "NekoRay/3.0"] {
            headers.insert("user-agent", ua.parse().unwrap());
            assert!(find_matching_rule(&headers, &rules).is_some(), "{ua} should match");
        }
    }

    #[test]
    fn ua_matching_incompatible() {
        let rules = hy2_rules();
        let mut headers = HeaderMap::new();
        for ua in &["Shadowrocket/1.0", "Surge/5.0", "QuantumultX", "curl/8.0",
                    "Mozilla/5.0", "clash/1.0"] {
            headers.insert("user-agent", ua.parse().unwrap());
            assert!(find_matching_rule(&headers, &rules).is_none(), "{ua} should NOT match");
        }
    }

    #[test]
    fn path_preview_redacts_the_subscription_token() {
        assert_eq!(path_preview("/sub/SECRET-TOKEN"), "/sub/...");
        assert_eq!(path_preview("/api/sub/SECRET-TOKEN"), "/api/...");
        assert_eq!(path_preview("/SECRET-TOKEN"), "/SECRET-TOKEN/...", "a bare token is its own first segment");
        assert_eq!(path_preview("/"), "/");
        assert_eq!(path_preview(""), "/");
    }

    #[test]
    fn rule_label_redacts_subscription_tokens() {
        let rule = InjectionRule {
            header: "User-Agent".to_string(),
            contains: vec!["happ".to_string()],
            links_source: vec![
                "/data/hy2.txt".to_string(),
                "https://panel.example.com/sub/SECRET".to_string(),
            ],
        };
        let label = rule_label(&rule);
        assert!(label.contains("/data/hy2.txt"));
        assert!(!label.contains("SECRET"), "token must not reach the log: {label}");
    }
}
