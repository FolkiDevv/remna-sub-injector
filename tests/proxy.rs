//! End-to-end tests: a client request goes through the injector to a mock upstream and back.

mod common;

use std::{sync::Arc, time::Duration};

use axum::{
    http::{Request, Response},
    routing::get,
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use common::*;
use sub_injector::{
    build_app,
    cache::LinksCache,
    config::InjectionRule,
    subscription::now_unix,
    AppState,
};
use tokio::net::TcpListener;

#[tokio::test]
async fn compatible_ua_gets_injection() {
    let upstream = start_mock(leak(fake_b64()), "text/plain").await;
    let links_file = write_temp_file(EXTRA_LINKS);
    let cfg = make_cfg(upstream, hy2_rules(&[&links_file]));

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
    let upstream = start_mock(leak(fake_b64()), "text/plain").await;
    let links_file = write_temp_file(EXTRA_LINKS);
    let cfg = make_cfg(upstream, hy2_rules(&[&links_file]));

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
    let cfg = make_cfg(upstream, hy2_rules(&[&links_file]));

    let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
    assert_eq!(status, 200);
    assert!(!body.contains("hysteria2://"), "yaml should never be injected");
    assert!(body.contains("proxies:"), "yaml content should be intact");
}

#[tokio::test]
async fn json_content_type_never_injected() {
    let upstream = start_mock(r#"{"proxies":[]}"#, "application/json").await;
    let links_file = write_temp_file(EXTRA_LINKS);
    let cfg = make_cfg(upstream, hy2_rules(&[&links_file]));

    let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
    assert_eq!(status, 200);
    assert!(!body.contains("hysteria2://"), "json should never be injected");
    assert!(body.contains("proxies"), "json content should be intact");
}

#[tokio::test]
async fn missing_links_file_passthrough() {
    let upstream = start_mock(leak(fake_b64()), "text/plain").await;
    let cfg = make_cfg(upstream, hy2_rules(&["/tmp/nonexistent-links-xyz.txt"]));

    let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
    let decoded = decode_b64(&body);
    assert_eq!(status, 200);
    assert!(!decoded.contains("hysteria2://"), "no injection when file missing");
    assert!(decoded.contains("vless://aaaaa"), "original links preserved");
}

#[tokio::test]
async fn upstream_down_returns_502() {
    let cfg = make_cfg("http://127.0.0.1:19999".to_string(), hy2_rules(&["/tmp/any.txt"]));
    let (status, _) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
    assert_eq!(status, 502);
}

#[tokio::test]
async fn custom_header_rule_matches() {
    let upstream = start_mock(leak(fake_b64()), "text/plain").await;
    let links_file = write_temp_file(EXTRA_LINKS);
    let cfg = make_cfg(
        upstream,
        vec![InjectionRule {
            header: "X-Client-Type".to_string(),
            contains: vec!["premium".to_string()],
            links_source: vec![links_file],
        }],
    );

    // С заголовком — инъекция происходит
    let req = Request::builder()
        .uri("/sub/TOKEN")
        .header("x-client-type", "premium")
        .body(axum::body::Body::empty())
        .unwrap();
    let (_, body) = call_request(build_app(cfg.clone()), req).await;
    assert!(decode_b64(&body).contains("hysteria2://"), "premium header should trigger injection");

    // Без заголовка — нет инъекции
    let req = Request::builder()
        .uri("/sub/TOKEN")
        .body(axum::body::Body::empty())
        .unwrap();
    let (_, body) = call_request(build_app(cfg.clone()), req).await;
    assert!(!decode_b64(&body).contains("hysteria2://"), "missing header should not trigger injection");
}

#[tokio::test]
async fn no_user_agent_no_match() {
    let upstream = start_mock(leak(fake_b64()), "text/plain").await;
    let links_file = write_temp_file(EXTRA_LINKS);
    let cfg = make_cfg(upstream, hy2_rules(&[&links_file]));

    let req = Request::builder()
        .uri("/sub/TOKEN")
        .body(axum::body::Body::empty())
        .unwrap();
    let (_, body) = call_request(build_app(cfg), req).await;
    let decoded = decode_b64(&body);
    assert!(!decoded.contains("hysteria2://"), "no UA should not trigger injection");
    assert!(decoded.contains("vless://aaaaa"), "original links preserved");
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
    settle().await;

    let cfg = make_cfg(format!("http://127.0.0.1:{port}"), hy2_rules(&["/tmp/any.txt"]));
    let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
    assert_eq!(status, 404);
    assert_eq!(body, "not found");
}

#[tokio::test]
async fn query_string_forwarded() {
    let upstream = start_echo_upstream(|uri: axum::http::Uri| {
        Response::builder()
            .header("content-type", "text/plain")
            .body(axum::body::Body::from(uri.query().unwrap_or("").to_string()))
            .unwrap()
    })
    .await;

    let cfg = make_cfg(upstream, vec![]);
    let req = Request::builder()
        .uri("/sub/TOKEN?foo=bar&baz=1")
        .body(axum::body::Body::empty())
        .unwrap();
    let (_, body) = call_request(build_app(cfg), req).await;
    assert_eq!(body, "foo=bar&baz=1");
}

#[tokio::test]
async fn hop_by_hop_headers_stripped() {
    let upstream = start_mock_with_headers(
        "hello",
        "text/plain",
        &[("connection", "keep-alive"), ("x-custom", "preserved")],
    )
    .await;

    let cfg = make_cfg(upstream, vec![]);
    let req = Request::builder()
        .uri("/sub/TOKEN")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = {
        use tower::ServiceExt;
        build_app(cfg).oneshot(req).await.unwrap()
    };
    let headers = resp.headers().clone();
    assert!(headers.get("connection").is_none(), "connection must be stripped");
    assert!(headers.get("x-custom").is_some(), "x-custom must be preserved");
}

#[tokio::test]
async fn different_ua_gets_different_links() {
    let upstream = start_mock(leak(fake_b64()), "text/plain").await;
    let hy2_file = write_temp_file("hysteria2://PASS@1.1.1.1:443#hy2-node");
    let clash_file = write_temp_file("vless://CLASH@2.2.2.2:443#clash-node");

    let cfg = make_cfg(
        upstream,
        vec![
            InjectionRule {
                header: "User-Agent".to_string(),
                contains: vec!["hiddify".to_string()],
                links_source: vec![hy2_file],
            },
            InjectionRule {
                header: "User-Agent".to_string(),
                contains: vec!["mihomo".to_string()],
                links_source: vec![clash_file],
            },
        ],
    );

    let (_, body) = call(build_app(cfg.clone()), "/sub/TOKEN", "hiddify/2.0").await;
    let decoded = decode_b64(&body);
    assert!(decoded.contains("hy2-node"), "hiddify should get hy2 links");
    assert!(!decoded.contains("clash-node"), "hiddify should NOT get clash links");

    let (_, body) = call(build_app(cfg.clone()), "/sub/TOKEN", "mihomo/1.0").await;
    let decoded = decode_b64(&body);
    assert!(decoded.contains("clash-node"), "mihomo should get clash links");
    assert!(!decoded.contains("hy2-node"), "mihomo should NOT get hy2 links");
}

// ── several sources on one rule ────────────────────────────────────────────────

#[tokio::test]
async fn all_sources_of_a_rule_are_merged() {
    let upstream = start_mock(leak(fake_b64()), "text/plain").await;
    let file = write_temp_file("hysteria2://PASS@1.1.1.1:443#from-file");
    let plain = MockSource::start("vless://PLAIN@2.2.2.2:443#from-plain-url").await;
    // A real subscription: base64, exactly what Remnawave or Marzban serves.
    let subscription =
        MockSource::start(&STANDARD.encode("trojan://PASS@3.3.3.3:443#from-subscription")).await;

    let cfg = make_cfg(
        upstream,
        hy2_rules(&[&file, &plain.url, &subscription.url]),
    );

    let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
    let decoded = decode_b64(&body);
    assert_eq!(status, 200);
    assert!(decoded.contains("vless://aaaaa"), "upstream links preserved");
    assert!(decoded.contains("from-file"), "file source merged");
    assert!(decoded.contains("from-plain-url"), "plain-text URL source merged");
    assert!(
        decoded.contains("from-subscription"),
        "a base64 subscription source must be decoded, not appended raw"
    );
    assert!(
        !decoded.lines().any(|line| line.starts_with("dHJvamFu")),
        "no raw base64 line should reach the client: {decoded}"
    );
}

#[tokio::test]
async fn duplicate_links_across_sources_appear_once() {
    let upstream = start_mock(leak(fake_b64()), "text/plain").await;
    let shared = "hysteria2://PASS@1.1.1.1:443#shared-node";
    let first = write_temp_file(shared);
    let second = write_temp_file(&format!("{shared}\nvless://X@2.2.2.2:443#only-in-second"));

    let cfg = make_cfg(upstream, hy2_rules(&[&first, &second]));
    let (_, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
    let decoded = decode_b64(&body);

    assert_eq!(decoded.matches("shared-node").count(), 1, "duplicate node must be merged: {decoded}");
    assert!(decoded.contains("only-in-second"));
}

#[tokio::test]
async fn a_broken_source_does_not_take_down_the_others() {
    let upstream = start_mock(leak(fake_b64()), "text/plain").await;
    let good = write_temp_file("hysteria2://PASS@1.1.1.1:443#good-node");
    let broken = MockSource::start("<!DOCTYPE html><html>502</html>").await;

    let cfg = make_cfg(upstream, hy2_rules(&[&broken.url, &good]));
    let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
    let decoded = decode_b64(&body);

    assert_eq!(status, 200);
    assert!(decoded.contains("good-node"), "the healthy source must still be injected");
    assert!(!decoded.contains("DOCTYPE"), "the error page must not reach the client");
}

#[tokio::test]
async fn a_source_subscription_that_expired_is_not_injected() {
    // The source's own account is dead: its body is stubs on 0.0.0.0, which must not be
    // passed on to this proxy's clients as if they were nodes.
    let upstream = start_mock(leak(fake_b64()), "text/plain").await;
    let dead = MockSource::start(&STANDARD.encode(SERVICE_LINKS)).await;
    let good = write_temp_file("hysteria2://PASS@1.1.1.1:443#good-node");

    let cfg = make_cfg(upstream, hy2_rules(&[&dead.url, &good]));
    let (_, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
    let decoded = decode_b64(&body);

    assert!(!decoded.contains("0.0.0.0"), "stub entries must not be injected: {decoded}");
    assert!(decoded.contains("good-node"));
}

#[tokio::test]
async fn every_source_failing_leaves_the_response_untouched() {
    let upstream = start_mock(leak(fake_b64()), "text/plain").await;
    let cfg = make_cfg(upstream, hy2_rules(&["/tmp/nope-a.txt", "/tmp/nope-b.txt"]));

    let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
    assert_eq!(status, 200);
    assert_eq!(decode_b64(&body), FAKE_LINKS, "body must pass through verbatim");
}

#[tokio::test]
async fn source_is_fetched_once_for_repeated_client_requests() {
    let upstream = start_mock(leak(fake_b64()), "text/plain").await;
    let source = MockSource::start("vless://PLAIN@2.2.2.2:443#cached-node").await;
    let cfg = make_cfg(upstream, hy2_rules(&[&source.url]));

    for _ in 0..3 {
        let (_, body) = call(build_app(cfg.clone()), "/sub/TOKEN", "happ/2.0").await;
        assert!(decode_b64(&body).contains("cached-node"));
    }
    assert_eq!(source.hits(), 1, "the source must be fetched once, not once per client request");
}

// ── service messages are proxied untouched ─────────────────────────────────────

#[tokio::test]
async fn reference_expired_response_not_injected() {
    let upstream = start_mock_with_headers(
        leak(STANDARD.encode(SERVICE_LINKS)),
        "text/plain",
        &[("subscription-userinfo", EXPIRED_USERINFO)],
    )
    .await;
    let links_file = write_temp_file(EXTRA_LINKS);
    let cfg = make_cfg(upstream, hy2_rules(&[&links_file]));

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
    let cfg = make_cfg(upstream, hy2_rules(&[&links_file]));

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
    let cfg = make_cfg(upstream, hy2_rules(&[&links_file]));

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
    let cfg = make_cfg(upstream, hy2_rules(&[&links_file]));

    let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
    let decoded = decode_b64(&body);
    assert_eq!(status, 200);
    assert!(!decoded.contains("hysteria2://"), "stub body must block injection");
    assert_eq!(decoded, SERVICE_LINKS);
}

#[tokio::test]
async fn a_service_message_does_not_even_touch_the_sources() {
    // The skip happens before the cache is consulted, so a blocked user never causes a fetch.
    let upstream = start_mock(leak(STANDARD.encode(SERVICE_LINKS)), "text/plain").await;
    let source = MockSource::start(EXTRA_LINKS).await;
    let cfg = make_cfg(upstream, hy2_rules(&[&source.url]));

    call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
    assert_eq!(source.hits(), 0);
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
    let cfg = make_cfg(upstream, hy2_rules(&[&links_file]));

    let (status, body) = call(build_app(cfg), "/sub/TOKEN", "happ/2.0").await;
    let decoded = decode_b64(&body);
    assert_eq!(status, 200);
    assert!(decoded.contains("hysteria2://"), "active subscription must still be injected");
    assert!(decoded.contains("vless://aaaaa"), "original links preserved");
}

#[tokio::test]
async fn cache_settings_reach_the_running_proxy() {
    // A rule whose source announces its own interval keeps serving links after the config
    // default would have expired.
    let upstream = start_mock(leak(fake_b64()), "text/plain").await;
    let source = MockSource::start("vless://PLAIN@2.2.2.2:443#announced").await;
    source.set_header("profile-update-interval", "12");

    let cache = LinksCache::new(Duration::from_secs(300), Duration::from_secs(3600), true);
    let cfg: Arc<AppState> = make_cfg_with_cache(upstream, hy2_rules(&[&source.url]), cache);

    for _ in 0..2 {
        let (_, body) = call(build_app(cfg.clone()), "/sub/TOKEN", "happ/2.0").await;
        assert!(decode_b64(&body).contains("announced"));
    }
    assert_eq!(source.hits(), 1);
}
