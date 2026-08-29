//! Shared fixtures for the integration tests: mock upstreams, mock links sources, and the
//! app state that ties them together.
#![allow(dead_code)]

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use axum::{
    body::to_bytes,
    http::{HeaderMap, Request, Response, Uri},
    routing::get,
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use sub_injector::{cache::LinksCache, config::InjectionRule, AppState};
use tokio::net::TcpListener;
use tower::ServiceExt;

pub const FAKE_LINKS: &str = "vless://aaaaa@1.2.3.4:443#node1\nss://bbbbbb@5.6.7.8:8388#node2";
/// Real body Remnawave returns for an expired subscription: placeholder entries on
/// 0.0.0.0:1 with the status as a percent-encoded remark.
pub const SERVICE_LINKS: &str = "vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?encryption=none&packetEncoding=xudp#%F0%9F%9A%A8%20Subscription%20expired\nvless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?encryption=none&packetEncoding=xudp#Contact%20support";
/// The header that came with it. expire = 2026-02-15, total = 0 means unlimited traffic.
pub const EXPIRED_USERINFO: &str = "upload=0; download=172266402; total=0; expire=1771177005";
pub const EXTRA_LINKS: &str = "hysteria2://PASS@10.0.0.1:5350?obfs=salamander&obfs-password=OBFS#node-fi\nhysteria2://PASS@10.0.0.2:5350?obfs=salamander&obfs-password=OBFS#node-pl";

pub fn fake_b64() -> String {
    STANDARD.encode(FAKE_LINKS.as_bytes())
}

pub fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

pub fn decode_b64(s: &str) -> String {
    let stripped: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    STANDARD
        .decode(&stripped)
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default()
}

pub fn write_temp_file(content: &str) -> String {
    let path = std::env::temp_dir().join(format!("test-extra-links-{}-{}.txt", std::process::id(), rand_suffix()));
    std::fs::write(&path, content).unwrap();
    path.to_str().unwrap().to_string()
}

pub fn rand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as u64;
    nanos * 1000 + COUNTER.fetch_add(1, Ordering::Relaxed) as u64
}

pub fn hy2_rules(links_source: &[&str]) -> Vec<InjectionRule> {
    vec![InjectionRule {
        header: "User-Agent".to_string(),
        contains: vec![
            "happ".to_string(), "hiddify".to_string(), "nekobox".to_string(),
            "nekoray".to_string(), "sing-box".to_string(), "clash.meta".to_string(),
            "mihomo".to_string(), "v2rayng".to_string(),
        ],
        links_source: links_source.iter().map(|s| s.to_string()).collect(),
    }]
}

pub fn make_cfg(upstream: String, injections: Vec<InjectionRule>) -> Arc<AppState> {
    make_cfg_with_cache(upstream, injections, LinksCache::new(Duration::from_secs(300), Duration::from_secs(3600), true))
}

pub fn make_cfg_with_cache(
    upstream: String,
    injections: Vec<InjectionRule>,
    links_cache: LinksCache,
) -> Arc<AppState> {
    Arc::new(AppState {
        upstream,
        bind_addr: "0.0.0.0:3020".to_string(),
        injections,
        client: reqwest::Client::new(),
        links_cache,
    })
}

pub async fn start_mock(body: &'static str, content_type: &'static str) -> String {
    start_mock_with_headers(body, content_type, &[]).await
}

pub async fn start_mock_with_headers(
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
    settle().await;
    format!("http://127.0.0.1:{}", port)
}

pub async fn call(app: Router, path: &str, ua: &str) -> (u16, String) {
    let req = Request::builder()
        .uri(path)
        .header("user-agent", ua)
        .body(axum::body::Body::empty())
        .unwrap();
    call_request(app, req).await
}

pub async fn call_request(app: Router, req: Request<axum::body::Body>) -> (u16, String) {
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// Give a just-spawned mock server a moment to bind.
pub async fn settle() {
    tokio::time::sleep(Duration::from_millis(20)).await;
}

/// A links source that counts how often it is actually fetched, so a test can tell a cache hit
/// from a refresh, and whose answer can be changed mid-test.
pub struct MockSource {
    pub url: String,
    hits: Arc<AtomicUsize>,
    state: Arc<Mutex<MockState>>,
}

#[derive(Clone)]
struct MockState {
    body: String,
    status: u16,
    headers: Vec<(String, String)>,
    /// When set, a conditional request carrying this validator is answered with 304.
    etag: Option<String>,
}

impl MockSource {
    pub async fn start(body: &str) -> Self {
        let state = Arc::new(Mutex::new(MockState {
            body: body.to_string(),
            status: 200,
            headers: Vec::new(),
            etag: None,
        }));
        let hits = Arc::new(AtomicUsize::new(0));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handler_state = state.clone();
        let handler_hits = hits.clone();
        tokio::spawn(async move {
            let app = Router::new().route(
                "/{*path}",
                get(move |headers: HeaderMap| {
                    let state = handler_state.clone();
                    let hits = handler_hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let state = state.lock().unwrap().clone();
                        let if_none_match = headers.get("if-none-match").and_then(|v| v.to_str().ok());
                        if let (Some(etag), Some(sent)) = (state.etag.as_deref(), if_none_match) {
                            if etag == sent {
                                return Response::builder()
                                    .status(304)
                                    .body(axum::body::Body::empty())
                                    .unwrap();
                            }
                        }
                        let mut builder = Response::builder()
                            .status(state.status)
                            .header("content-type", "text/plain");
                        if let Some(etag) = &state.etag {
                            builder = builder.header("etag", etag);
                        }
                        for (name, value) in &state.headers {
                            builder = builder.header(name, value);
                        }
                        builder.body(axum::body::Body::from(state.body.clone())).unwrap()
                    }
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });
        settle().await;

        Self { url: format!("http://127.0.0.1:{port}/links"), hits, state }
    }

    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    pub fn set_body(&self, body: &str) {
        self.state.lock().unwrap().body = body.to_string();
    }

    pub fn set_status(&self, status: u16) {
        self.state.lock().unwrap().status = status;
    }

    pub fn set_header(&self, name: &str, value: &str) {
        self.state.lock().unwrap().headers.push((name.to_string(), value.to_string()));
    }

    pub fn set_etag(&self, etag: &str) {
        self.state.lock().unwrap().etag = Some(etag.to_string());
    }
}

/// A mock upstream that echoes back whatever it is asked, for the header/query plumbing tests.
pub async fn start_echo_upstream<F, R>(handler: F) -> String
where
    F: Fn(Uri) -> R + Clone + Send + Sync + 'static,
    R: axum::response::IntoResponse + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let app = Router::new().route(
            "/{*path}",
            get(move |uri: Uri| {
                let handler = handler.clone();
                async move { handler(uri) }
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });
    settle().await;
    format!("http://127.0.0.1:{port}")
}
