//! What a links source sees when the injector fetches it: the injector's own headers, never the
//! client's — and how a source that answers them with the wrong format is retried.

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

async fn collect(cache: &LinksCache, url: &str) -> Vec<String> {
    cache.collect(std::slice::from_ref(&url.to_string()), &reqwest::Client::new()).await
}

#[tokio::test]
async fn a_url_source_is_fetched_as_a_client_that_gets_a_link_list() {
    let source = MockSource::start(LINK).await;
    let cache = cache(SourceHeaders::defaults("http://upstream:2096"));

    collect(&cache, &source.url).await;

    let ua = source.seen_header("user-agent").expect("a source must see a user-agent");
    assert!(ua.to_lowercase().contains("v2rayng"), "user-agent was {ua:?}");
    assert_eq!(source.seen_header("x-device-os").as_deref(), Some("Android"));
    assert_eq!(source.seen_header("x-ver-os").as_deref(), Some("14"));
    assert_eq!(source.seen_header("x-device-model").as_deref(), Some("Pixel 7"));
    assert_eq!(
        source.seen_header("x-hwid").map(|hwid| hwid.len()),
        Some(36),
        "the device id is sent, in the shape Remnawave documents"
    );
}

#[tokio::test]
async fn the_hwid_is_the_same_on_every_fetch() {
    let source = MockSource::start(LINK).await;
    let cache = cache(SourceHeaders::defaults("http://upstream:2096"));

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
async fn a_revalidation_carries_both_the_validator_and_the_source_headers() {
    let source = MockSource::start(LINK).await;
    source.set_etag("\"v1\"");
    let cache = cache(SourceHeaders::defaults("http://upstream:2096"));

    collect(&cache, &source.url).await;
    collect(&cache, &source.url).await;

    assert_eq!(source.seen_header("if-none-match").as_deref(), Some("\"v1\""));
    assert!(source.seen_header("user-agent").unwrap().to_lowercase().contains("v2rayng"));
}

#[tokio::test]
async fn client_headers_never_reach_a_source() {
    let source = MockSource::start(LINK).await;
    let upstream = start_mock(leak(fake_b64()), "text/plain").await;
    let app = sub_injector::build_app(make_cfg_with_cache(
        upstream,
        hy2_rules(&[&source.url]),
        cache(SourceHeaders::defaults("http://upstream:2096")),
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
    assert_eq!(source.seen_header("user-agent").as_deref(), Some("v2rayNG/1.10.5"));
}

// ── a source that answers with the wrong format ────────────────────────────────

/// What the panel in the bug report serves a Happ-shaped user-agent: an array of ready-made
/// Xray configs. It carries nodes, but not one proxy URI to append to a subscription.
const XRAY_PROFILE: &str =
    "[{\"remarks\":\"Auto\",\"log\":{\"loglevel\":\"warning\"},\"outbounds\":[{\"protocol\":\"vless\"}]}]";

#[tokio::test]
async fn a_source_that_serves_a_profile_is_refetched_as_another_client() {
    let source = MockSource::start(XRAY_PROFILE).await;
    // Only one of the fallbacks gets a link list — as on a real panel, the format is keyed to
    // the client family.
    source.answer_client("hiddify", LINK);
    let cache = cache(SourceHeaders::defaults("http://upstream:2096"));

    let links = collect(&cache, &source.url).await;

    assert_eq!(links, vec![LINK], "the links behind the wrong format still reach the client");
    assert!(
        source.seen_header("user-agent").unwrap().to_lowercase().contains("hiddify"),
        "the retry asks as a different client"
    );
    assert_eq!(source.hits(), 2, "the default client first, then one fallback");
}

#[tokio::test]
async fn the_client_a_source_answers_is_remembered() {
    let source = MockSource::start(XRAY_PROFILE).await;
    source.answer_client("hiddify", LINK);
    let cache = cache(SourceHeaders::defaults("http://upstream:2096"));

    collect(&cache, &source.url).await;
    let after_first = source.hits();
    let links = collect(&cache, &source.url).await;

    assert_eq!(links, vec![LINK]);
    assert_eq!(
        source.hits() - after_first,
        1,
        "the next refresh asks as the client that worked, instead of failing its way there again"
    );
}

#[tokio::test]
async fn a_source_that_serves_a_profile_to_everyone_fails_once_and_stops() {
    let source = MockSource::start(XRAY_PROFILE).await;
    let cache = cache(SourceHeaders::defaults("http://upstream:2096"));

    let links = collect(&cache, &source.url).await;

    assert!(links.is_empty(), "a profile carries no links to inject");
    assert_eq!(
        source.hits(),
        1 + SourceHeaders::defaults("seed").format_fallbacks().len(),
        "every client is tried once, and none of them twice"
    );
}

#[tokio::test]
async fn a_pinned_user_agent_is_never_second_guessed() {
    let source = MockSource::start(XRAY_PROFILE).await;
    source.answer_client("hiddify", LINK);
    let headers = SourceHeaders::from_config(
        "http://upstream:2096",
        &overrides(&[("user-agent", "Happ/2.0.0 (com.happproxy; iOS 18.3.0)")]),
    );

    let links = collect(&cache(headers), &source.url).await;

    assert!(links.is_empty(), "the operator named the client; the answer is theirs to fix");
    assert_eq!(source.hits(), 1, "no fetch behind the operator's back");
}

#[tokio::test]
async fn a_source_that_is_simply_down_is_not_retried_as_other_clients() {
    let source = MockSource::start(LINK).await;
    source.set_status(503);
    let cache = cache(SourceHeaders::defaults("http://upstream:2096"));

    collect(&cache, &source.url).await;

    assert_eq!(source.hits(), 1, "another user-agent cannot fix an HTTP 503");
}
