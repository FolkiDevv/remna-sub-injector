use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
    routing::get,
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{env, fs, sync::Arc};
use tokio::net::TcpListener;

#[derive(Debug, serde::Deserialize)]
pub struct FileConfig {
    pub upstream_url: String,
    pub bind_addr: Option<String>,
    pub injections: Vec<InjectionRule>,
}

#[derive(Debug, serde::Deserialize)]
pub struct InjectionRule {
    pub header: String,
    pub contains: Vec<String>,
    pub links_source: String,
}

pub struct AppState {
    pub upstream: String,
    pub bind_addr: String,
    pub injections: Vec<InjectionRule>,
    pub client: reqwest::Client,
}

pub fn load_config(path: &str) -> FileConfig {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Cannot read config file {path}: {e}"));
    toml::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid config file {path}: {e}"))
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

pub async fn load_extra_links_from_source(source: &str, client: &reqwest::Client) -> String {
    if source.starts_with("http://") || source.starts_with("https://") {
        match client.get(source).send().await {
            Ok(resp) => {
                if resp.content_length().unwrap_or(0) > MAX_BODY_SIZE {
                    eprintln!("[sub-injector] links source response too large: {source}");
                    return String::new();
                }
                let text = resp.text().await.unwrap_or_default();
                if text.len() as u64 > MAX_BODY_SIZE {
                    eprintln!("[sub-injector] links source response too large: {source}");
                    return String::new();
                }
                text.trim().to_string()
            }
            Err(e) => {
                eprintln!("[sub-injector] failed to fetch links from {source}: {e}");
                String::new()
            }
        }
    } else {
        fs::read_to_string(source)
            .unwrap_or_default()
            .trim()
            .to_string()
    }
}

pub fn decode_sub_body(body: &[u8]) -> Option<String> {
    // Strip whitespace (newlines) before decoding — some upstreams wrap base64 at 76 chars
    let stripped: Vec<u8> = body.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    let decoded = STANDARD.decode(&stripped).ok()?;
    String::from_utf8(decoded).ok()
}

pub fn encode_sub_body(text: &str) -> Vec<u8> {
    STANDARD.encode(text.as_bytes()).into_bytes()
}

pub fn inject_links(body: &[u8], extra: &str) -> Vec<u8> {
    match decode_sub_body(body) {
        Some(text) => encode_sub_body(&format!("{}\n{}", text.trim(), extra)),
        None => body.to_vec(),
    }
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

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

const MAX_BODY_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

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

    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/").to_string();
    let ua_preview = headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("").chars().take(40).collect::<String>();
    // Log only the first two path segments to avoid leaking subscription tokens
    let path_preview = uri.path().splitn(4, '/').take(3).collect::<Vec<_>>().join("/");
    eprintln!("[sub-injector] >> GET {path_preview}/... ua={ua_preview:?}");

    let mut req = cfg.client.get(&upstream_url);

    for (name, value) in &headers {
        if name.as_str().to_lowercase() == "connection" {
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
        matched_rule.map(|r| r.links_source.as_str()).unwrap_or("none"),
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
                        let extra = load_extra_links_from_source(&rule.links_source, &cfg.client).await;
                        eprintln!("[sub-injector] extra_len={}", extra.len());
                        if extra.is_empty() {
                            body_bytes
                        } else {
                            let injected = encode_sub_body(&format!("{}\n{}", text.trim(), extra));
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

pub fn build_app(cfg: Arc<AppState>) -> Router {
    Router::new()
        .route("/{*path}", get(proxy))
        .route("/", get(proxy))
        .with_state(cfg)
}

#[tokio::main]
async fn main() {
    let config_path = env::var("CONFIG_FILE").unwrap_or_else(|_| "config.toml".to_string());
    let file_cfg = load_config(&config_path);
    let bind_addr = file_cfg.bind_addr.unwrap_or_else(|| "0.0.0.0:3020".to_string());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("Failed to build HTTP client");

    let cfg = Arc::new(AppState {
        upstream: file_cfg.upstream_url,
        bind_addr: bind_addr.clone(),
        injections: file_cfg.injections,
        client,
    });

    let app = build_app(cfg);

    let listener = TcpListener::bind(&bind_addr)
        .await
        .expect("Failed to bind");

    println!("sub-injector v{} listening on {bind_addr}", env!("CARGO_PKG_VERSION"));
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, http::Request};
    use tower::ServiceExt;

    const FAKE_LINKS: &str = "vless://aaaaa@1.2.3.4:443#node1\nss://bbbbbb@5.6.7.8:8388#node2";
    /// Real body Remnawave returns for an expired subscription: placeholder entries on
    /// 0.0.0.0:1 with the status as a percent-encoded remark.
    const SERVICE_LINKS: &str = "vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?encryption=none&packetEncoding=xudp#%F0%9F%9A%A8%20Subscription%20expired\nvless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?encryption=none&packetEncoding=xudp#Contact%20support";
    /// The header that came with it. expire = 2026-02-15, total = 0 means unlimited traffic.
    const EXPIRED_USERINFO: &str = "upload=0; download=172266402; total=0; expire=1771177005";
    const EXTRA_LINKS: &str = "hysteria2://PASS@10.0.0.1:5350?obfs=salamander&obfs-password=OBFS#node-fi\nhysteria2://PASS@10.0.0.2:5350?obfs=salamander&obfs-password=OBFS#node-pl";

    fn fake_b64() -> String {
        STANDARD.encode(FAKE_LINKS.as_bytes())
    }

    fn leak(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    fn decode_b64(s: &str) -> String {
        let stripped: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        STANDARD
            .decode(&stripped)
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default()
    }

    fn write_temp_file(content: &str) -> String {
        let path = std::env::temp_dir().join(format!("test-extra-links-{}-{}.txt", std::process::id(), rand_suffix()));
        fs::write(&path, content).unwrap();
        path.to_str().unwrap().to_string()
    }

    fn rand_suffix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as u64
    }

    fn hy2_rules(links_source: &str) -> Vec<InjectionRule> {
        vec![InjectionRule {
            header: "User-Agent".to_string(),
            contains: vec![
                "happ".to_string(), "hiddify".to_string(), "nekobox".to_string(),
                "nekoray".to_string(), "sing-box".to_string(), "clash.meta".to_string(),
                "mihomo".to_string(), "v2rayng".to_string(),
            ],
            links_source: links_source.to_string(),
        }]
    }

    fn make_cfg(upstream: String, injections: Vec<InjectionRule>) -> Arc<AppState> {
        Arc::new(AppState {
            upstream,
            bind_addr: "0.0.0.0:3020".to_string(),
            injections,
            client: reqwest::Client::new(),
        })
    }

    async fn start_mock(body: &'static str, content_type: &'static str) -> String {
        start_mock_with_headers(body, content_type, &[]).await
    }

    async fn start_mock_with_headers(
        body: &'static str,
        content_type: &'static str,
        extra: &'static [(&'static str, &'static str)],
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let app = Router::new().route(
                "/{*path}",
                get(move || async move {
                    let mut builder = Response::builder().header("content-type", content_type);
                    for (name, value) in extra {
                        builder = builder.header(*name, *value);
                    }
                    builder.body(axum::body::Body::from(body)).unwrap()
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        format!("http://127.0.0.1:{}", port)
    }

    async fn call(app: Router, path: &str, ua: &str) -> (u16, String) {
        let req = Request::builder()
            .uri(path)
            .header("user-agent", ua)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status().as_u16();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    // ── unit tests ─────────────────────────────────────────────────────────────

    #[test]
    fn ua_matching_compatible() {
        let rules = hy2_rules("/tmp/fake.txt");
        let mut headers = HeaderMap::new();
        for ua in &["happ/2.0", "Hiddify/1.5", "NekoBox/3.0", "sing-box/1.0",
                    "clash.meta/1.18", "Mihomo/1.0", "v2rayng/1.8", "NekoRay/3.0"] {
            headers.insert("user-agent", ua.parse().unwrap());
            assert!(find_matching_rule(&headers, &rules).is_some(), "{ua} should match");
        }
    }

    #[test]
    fn ua_matching_incompatible() {
        let rules = hy2_rules("/tmp/fake.txt");
        let mut headers = HeaderMap::new();
        for ua in &["Shadowrocket/1.0", "Surge/5.0", "QuantumultX", "curl/8.0",
                    "Mozilla/5.0", "clash/1.0"] {
            headers.insert("user-agent", ua.parse().unwrap());
            assert!(find_matching_rule(&headers, &rules).is_none(), "{ua} should NOT match");
        }
    }

    #[test]
    fn inject_links_roundtrip() {
        let body = fake_b64().into_bytes();
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
    fn load_config_parses_correctly() {
        let toml_content = r#"
upstream_url = "http://upstream:2096"
bind_addr = "0.0.0.0:3020"

[[injections]]
header = "User-Agent"
contains = ["hiddify", "happ"]
links_source = "/data/hy2.txt"
"#;
        let path = write_temp_file(toml_content);
        let cfg = load_config(&path);
        assert_eq!(cfg.upstream_url, "http://upstream:2096");
        assert_eq!(cfg.bind_addr, Some("0.0.0.0:3020".to_string()));
        assert_eq!(cfg.injections.len(), 1);
        assert_eq!(cfg.injections[0].contains, vec!["hiddify", "happ"]);
        assert_eq!(cfg.injections[0].links_source, "/data/hy2.txt");
    }

    #[tokio::test]
    async fn load_links_from_file() {
        let path = write_temp_file(EXTRA_LINKS);
        let client = reqwest::Client::new();
        let result = load_extra_links_from_source(&path, &client).await;
        assert_eq!(result, EXTRA_LINKS);
    }

    #[tokio::test]
    async fn load_links_missing_file_returns_empty() {
        let client = reqwest::Client::new();
        let result = load_extra_links_from_source("/tmp/definitely-does-not-exist-xyz.txt", &client).await;
        assert!(result.is_empty());
    }

    // ── integration tests ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn compatible_ua_gets_injection() {
        let upstream = start_mock(Box::leak(fake_b64().into_boxed_str()), "text/plain").await;
        let links_file = write_temp_file(EXTRA_LINKS);
        let cfg = make_cfg(upstream, hy2_rules(&links_file));

        for ua in &["happ/2.0", "Hiddify/1.5", "nekobox/3.0", "sing-box/1.0",
                    "clash.meta/1.18", "mihomo/1.0", "v2rayng/1.8"] {
            let (status, body) = call(build_app(cfg.clone()), "/sub/TOKEN", ua).await;
            let decoded = decode_b64(&body);
            assert_eq!(status, 200, "UA: {ua}");
            assert!(decoded.contains("hysteria2://"), "UA {ua} should inject hysteria2");
            assert!(decoded.contains("vless://aaaaa"), "UA {ua} should preserve original links");
        }
    }

    #[tokio::test]
    async fn incompatible_ua_passes_through() {
        let upstream = start_mock(Box::leak(fake_b64().into_boxed_str()), "text/plain").await;
        let links_file = write_temp_file(EXTRA_LINKS);
        let cfg = make_cfg(upstream, hy2_rules(&links_file));

        for ua in &["Shadowrocket/1.0", "Surge/5.0", "QuantumultX", "Mozilla/5.0"] {
            let (status, body) = call(build_app(cfg.clone()), "/sub/TOKEN", ua).await;
            let decoded = decode_b64(&body);
            assert_eq!(status, 200, "UA: {ua}");
            assert!(!decoded.contains("hysteria2://"), "UA {ua} should NOT inject");
            assert!(decoded.contains("vless://aaaaa"), "UA {ua} should preserve original links");
        }
    }

    #[tokio::test]
    async fn yaml_content_type_never_injected() {
        let upstream = start_mock("proxies:\n  - name: node1\n    type: vless", "text/yaml").await;
        let links_file = write_temp_file(EXTRA_LINKS);
        let cfg = make_cfg(upstream, hy2_rules(&links_file));

        let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
        assert_eq!(status, 200);
        assert!(!body.contains("hysteria2://"), "yaml should never be injected");
        assert!(body.contains("proxies:"), "yaml content should be intact");
    }

    #[tokio::test]
    async fn missing_links_file_passthrough() {
        let upstream = start_mock(Box::leak(fake_b64().into_boxed_str()), "text/plain").await;
        let cfg = make_cfg(upstream, hy2_rules("/tmp/nonexistent-links-xyz.txt"));

        let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
        let decoded = decode_b64(&body);
        assert_eq!(status, 200);
        assert!(!decoded.contains("hysteria2://"), "no injection when file missing");
        assert!(decoded.contains("vless://aaaaa"), "original links preserved");
    }

    #[tokio::test]
    async fn upstream_down_returns_502() {
        let cfg = make_cfg(
            "http://127.0.0.1:19999".to_string(),
            hy2_rules("/tmp/any.txt"),
        );
        let (status, _) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
        assert_eq!(status, 502);
    }

    // ── новые тесты ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn load_links_from_url() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let app = Router::new().route(
                "/links",
                get(|| async { EXTRA_LINKS }),
            );
            axum::serve(listener, app).await.unwrap();
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

        let client = reqwest::Client::new();
        let url = format!("http://127.0.0.1:{port}/links");
        let result = load_extra_links_from_source(&url, &client).await;
        assert_eq!(result, EXTRA_LINKS);
    }

    #[tokio::test]
    async fn load_links_url_unreachable_returns_empty() {
        let client = reqwest::Client::new();
        let result = load_extra_links_from_source("http://127.0.0.1:19998/links", &client).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn json_content_type_never_injected() {
        let upstream = start_mock(r#"{"proxies":[]}"#, "application/json").await;
        let links_file = write_temp_file(EXTRA_LINKS);
        let cfg = make_cfg(upstream, hy2_rules(&links_file));

        let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
        assert_eq!(status, 200);
        assert!(!body.contains("hysteria2://"), "json should never be injected");
        assert!(body.contains("proxies"), "json content should be intact");
    }

    #[tokio::test]
    async fn custom_header_rule_matches() {
        let upstream = start_mock(Box::leak(fake_b64().into_boxed_str()), "text/plain").await;
        let links_file = write_temp_file(EXTRA_LINKS);
        let cfg = Arc::new(AppState {
            upstream,
            bind_addr: "0.0.0.0:3020".to_string(),
            injections: vec![InjectionRule {
                header: "X-Client-Type".to_string(),
                contains: vec!["premium".to_string()],
                links_source: links_file,
            }],
            client: reqwest::Client::new(),
        });

        // С заголовком — инъекция происходит
        let req = Request::builder()
            .uri("/sub/TOKEN")
            .header("x-client-type", "premium")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = build_app(cfg.clone()).oneshot(req).await.unwrap();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let decoded = decode_b64(&String::from_utf8_lossy(&bytes));
        assert!(decoded.contains("hysteria2://"), "premium header should trigger injection");

        // Без заголовка — нет инъекции
        let req = Request::builder()
            .uri("/sub/TOKEN")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = build_app(cfg.clone()).oneshot(req).await.unwrap();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let decoded = decode_b64(&String::from_utf8_lossy(&bytes));
        assert!(!decoded.contains("hysteria2://"), "missing header should not trigger injection");
    }

    #[tokio::test]
    async fn no_user_agent_no_match() {
        let upstream = start_mock(Box::leak(fake_b64().into_boxed_str()), "text/plain").await;
        let links_file = write_temp_file(EXTRA_LINKS);
        let cfg = make_cfg(upstream, hy2_rules(&links_file));

        let req = Request::builder()
            .uri("/sub/TOKEN")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = build_app(cfg).oneshot(req).await.unwrap();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let decoded = decode_b64(&String::from_utf8_lossy(&bytes));
        assert!(!decoded.contains("hysteria2://"), "no UA should not trigger injection");
        assert!(decoded.contains("vless://aaaaa"), "original links preserved");
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

    #[tokio::test]
    async fn upstream_non200_status_proxied() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let app = Router::new().route(
                "/{*path}",
                get(|| async {
                    Response::builder()
                        .status(404)
                        .body(axum::body::Body::from("not found"))
                        .unwrap()
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        let upstream = format!("http://127.0.0.1:{port}");

        let cfg = make_cfg(upstream, hy2_rules("/tmp/any.txt"));
        let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
        assert_eq!(status, 404);
        assert_eq!(body, "not found");
    }

    #[tokio::test]
    async fn query_string_forwarded() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let app = Router::new().route(
                "/{*path}",
                get(|uri: Uri| async move {
                    let qs = uri.query().unwrap_or("").to_string();
                    Response::builder()
                        .header("content-type", "text/plain")
                        .body(axum::body::Body::from(qs))
                        .unwrap()
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        let upstream = format!("http://127.0.0.1:{port}");

        let cfg = make_cfg(upstream, vec![]);
        let req = Request::builder()
            .uri("/sub/TOKEN?foo=bar&baz=1")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = build_app(cfg).oneshot(req).await.unwrap();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&bytes), "foo=bar&baz=1");
    }

    #[tokio::test]
    async fn hop_by_hop_headers_stripped() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let app = Router::new().route(
                "/{*path}",
                get(|| async {
                    Response::builder()
                        .header("content-type", "text/plain")
                        .header("connection", "keep-alive")
                        .header("x-custom", "preserved")
                        .body(axum::body::Body::from("hello"))
                        .unwrap()
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        let upstream = format!("http://127.0.0.1:{port}");

        let cfg = make_cfg(upstream, vec![]);
        let req = Request::builder()
            .uri("/sub/TOKEN")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = build_app(cfg).oneshot(req).await.unwrap();
        let headers = resp.headers().clone();
        assert!(headers.get("connection").is_none(), "connection must be stripped");
        assert!(headers.get("x-custom").is_some(), "x-custom must be preserved");
    }

    #[tokio::test]
    async fn different_ua_gets_different_links() {
        let upstream = start_mock(Box::leak(fake_b64().into_boxed_str()), "text/plain").await;
        let hy2_file = write_temp_file("hysteria2://PASS@1.1.1.1:443#hy2-node");
        let clash_file = write_temp_file("vless://CLASH@2.2.2.2:443#clash-node");

        let cfg = Arc::new(AppState {
            upstream,
            bind_addr: "0.0.0.0:3020".to_string(),
            injections: vec![
                InjectionRule {
                    header: "User-Agent".to_string(),
                    contains: vec!["hiddify".to_string()],
                    links_source: hy2_file,
                },
                InjectionRule {
                    header: "User-Agent".to_string(),
                    contains: vec!["mihomo".to_string()],
                    links_source: clash_file,
                },
            ],
            client: reqwest::Client::new(),
        });

        let (_, body) = call(build_app(cfg.clone()), "/sub/TOKEN", "hiddify/2.0").await;
        let decoded = decode_b64(&body);
        assert!(decoded.contains("hy2-node"), "hiddify should get hy2 links");
        assert!(!decoded.contains("clash-node"), "hiddify should NOT get clash links");

        let (_, body) = call(build_app(cfg.clone()), "/sub/TOKEN", "mihomo/1.0").await;
        let decoded = decode_b64(&body);
        assert!(decoded.contains("clash-node"), "mihomo should get clash links");
        assert!(!decoded.contains("hy2-node"), "mihomo should NOT get hy2 links");
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

    // ── service messages are proxied untouched ─────────────────────────────────

    #[tokio::test]
    async fn reference_expired_response_not_injected() {
        let upstream = start_mock_with_headers(
            leak(STANDARD.encode(SERVICE_LINKS)),
            "text/plain",
            &[("subscription-userinfo", EXPIRED_USERINFO)],
        )
        .await;
        let links_file = write_temp_file(EXTRA_LINKS);
        let cfg = make_cfg(upstream, hy2_rules(&links_file));

        let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
        let decoded = decode_b64(&body);
        assert_eq!(status, 200);
        assert!(!decoded.contains("hysteria2://"), "expired subscription must not be injected");
        assert_eq!(decoded, SERVICE_LINKS, "service message must pass through verbatim");
    }

    #[tokio::test]
    async fn expired_userinfo_header_blocks_injection() {
        // Body looks like a normal subscription; only the header says it is expired.
        let upstream = start_mock_with_headers(
            leak(fake_b64()),
            "text/plain",
            &[("subscription-userinfo", "upload=0; download=0; total=0; expire=1771177005")],
        )
        .await;
        let links_file = write_temp_file(EXTRA_LINKS);
        let cfg = make_cfg(upstream, hy2_rules(&links_file));

        let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
        let decoded = decode_b64(&body);
        assert_eq!(status, 200);
        assert!(!decoded.contains("hysteria2://"), "expired header must block injection");
        assert!(decoded.contains("vless://aaaaa"), "original body preserved");
    }

    #[tokio::test]
    async fn traffic_limit_blocks_injection() {
        let upstream = start_mock_with_headers(
            leak(fake_b64()),
            "text/plain",
            &[("subscription-userinfo", "upload=500; download=600; total=1000; expire=0")],
        )
        .await;
        let links_file = write_temp_file(EXTRA_LINKS);
        let cfg = make_cfg(upstream, hy2_rules(&links_file));

        let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
        let decoded = decode_b64(&body);
        assert_eq!(status, 200);
        assert!(!decoded.contains("hysteria2://"), "exhausted traffic must block injection");
        assert!(decoded.contains("vless://aaaaa"), "original body preserved");
    }

    #[tokio::test]
    async fn service_host_body_blocks_injection_without_header() {
        // A deactivated user can still be within their expiry and traffic budget, so the
        // stub body is the only signal — this is the case the header cannot catch.
        let upstream = start_mock(leak(STANDARD.encode(SERVICE_LINKS)), "text/plain").await;
        let links_file = write_temp_file(EXTRA_LINKS);
        let cfg = make_cfg(upstream, hy2_rules(&links_file));

        let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
        let decoded = decode_b64(&body);
        assert_eq!(status, 200);
        assert!(!decoded.contains("hysteria2://"), "stub body must block injection");
        assert_eq!(decoded, SERVICE_LINKS);
    }

    #[tokio::test]
    async fn active_subscription_still_injected() {
        // Regression guard: a live subscription must keep getting the extra links.
        let future = now_unix() + 30 * 24 * 3600;
        let header = leak(format!("upload=10; download=20; total=0; expire={future}"));
        let upstream = start_mock_with_headers(
            leak(fake_b64()),
            "text/plain",
            Box::leak(Box::new([("subscription-userinfo", header)])),
        )
        .await;
        let links_file = write_temp_file(EXTRA_LINKS);
        let cfg = make_cfg(upstream, hy2_rules(&links_file));

        let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
        let decoded = decode_b64(&body);
        assert_eq!(status, 200);
        assert!(decoded.contains("hysteria2://"), "active subscription must still be injected");
        assert!(decoded.contains("vless://aaaaa"), "original links preserved");
    }
}
