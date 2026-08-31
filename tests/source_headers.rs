//! What a links source sees when the injector fetches it: the injector's own Happ-shaped headers,
//! never the client's.

mod common;

use std::{collections::HashMap, time::Duration};

use common::*;
use sub_injector::{
    cache::LinksCache,
    links::{TtlPolicy, MAX_TTL},
    source_headers::{derive_hwid, SourceHeaders},
};

const LINK: &str = "vless://A@1.1.1.1:443#node";

/// No lower bound on the TTL, so a second `collect` really refetches instead of being served from
/// the 30-second production minimum.
fn cache(headers: SourceHeaders) -> LinksCache {
    let policy = TtlPolicy {
        default: Duration::ZERO,
        min: Duration::ZERO,
        max: MAX_TTL,
        respect_headers: false,
    };
    LinksCache::with_policy(policy, Duration::from_secs(60)).with_source_headers(headers)
}

fn overrides(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs.iter().map(|(n, v)| ((*n).to_string(), (*v).to_string())).collect()
}

async fn collect(cache: &LinksCache, url: &str) {
    cache.collect(&[url.to_string()], &reqwest::Client::new()).await;
}

#[tokio::test]
async fn a_url_source_is_fetched_as_a_happ_client() {
    let source = MockSource::start(LINK).await;
    let cache = cache(SourceHeaders::happ_defaults("http://upstream:2096"));

    collect(&cache, &source.url).await;

    let ua = source.seen_header("user-agent").expect("a source must see a user-agent");
    assert!(ua.to_lowercase().contains("happ"), "user-agent was {ua:?}");
    assert_eq!(source.seen_header("x-device-os").as_deref(), Some("iOS"));
    assert_eq!(source.seen_header("x-ver-os").as_deref(), Some("18.3"));
    assert_eq!(source.seen_header("x-device-model").as_deref(), Some("iPhone"));
    assert_eq!(
        source.seen_header("x-hwid").map(|hwid| hwid.len()),
        Some(36),
        "the device id is sent, in the shape Remnawave documents"
    );
}

#[tokio::test]
async fn the_hwid_is_the_same_on_every_fetch() {
    let source = MockSource::start(LINK).await;
    let cache = cache(SourceHeaders::happ_defaults("http://upstream:2096"));

    collect(&cache, &source.url).await;
    let first = source.seen_header("x-hwid");
    collect(&cache, &source.url).await;

    assert_eq!(source.hits(), 2, "the TTL is zero, so the second call refetches");
    assert_eq!(source.seen_header("x-hwid"), first, "a source must not see a new device each time");
}

#[tokio::test]
async fn configured_headers_replace_and_drop_the_defaults() {
    let source = MockSource::start(LINK).await;
    let headers = SourceHeaders::from_config(
        "http://upstream:2096",
        &overrides(&[("User-Agent", "Happ/9.9.9"), ("x-device-model", ""), ("x-custom", "1")]),
    );

    collect(&cache(headers), &source.url).await;

    assert_eq!(source.seen_header("user-agent").as_deref(), Some("Happ/9.9.9"));
    assert_eq!(source.seen_header("x-device-model"), None, "an empty value drops the header");
    assert_eq!(source.seen_header("x-custom").as_deref(), Some("1"));
    assert!(source.seen_header("x-hwid").is_some(), "the untouched defaults still go out");
}

#[tokio::test]
async fn a_revalidation_carries_both_the_validator_and_the_happ_headers() {
    let source = MockSource::start(LINK).await;
    source.set_etag("\"v1\"");
    let cache = cache(SourceHeaders::happ_defaults("http://upstream:2096"));

    collect(&cache, &source.url).await;
    collect(&cache, &source.url).await;

    assert_eq!(source.seen_header("if-none-match").as_deref(), Some("\"v1\""));
    assert!(source.seen_header("user-agent").unwrap().to_lowercase().contains("happ"));
}

#[tokio::test]
async fn client_headers_never_reach_a_source() {
    let source = MockSource::start(LINK).await;
    let upstream = start_mock(leak(fake_b64()), "text/plain").await;
    let app = sub_injector::build_app(make_cfg_with_cache(
        upstream,
        hy2_rules(&[&source.url]),
        cache(SourceHeaders::happ_defaults("http://upstream:2096")),
    ));

    let req = axum::http::Request::builder()
        .uri("/sub/TOKEN")
        .header("user-agent", "Happ/1.2.3 (client)")
        .header("x-hwid", "CLIENT-DEVICE-ID")
        .header("cookie", "session=SECRET")
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, _) = call_request(app, req).await;

    assert_eq!(status, 200);
    assert_eq!(
        source.seen_header("x-hwid").as_deref(),
        Some(derive_hwid("http://upstream:2096").as_str()),
        "the source sees the injector's own device id, not the client's"
    );
    assert_eq!(source.seen_header("cookie"), None, "the client's credentials never leave for a third-party source");
    assert_eq!(source.seen_header("user-agent").as_deref(), Some("Happ/2.0.0 (com.happproxy; iOS 18.3.0)"));
}
