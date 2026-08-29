//! How the links cache behaves over time: when it refetches, and what it serves when a source
//! stops answering.

mod common;

use std::time::Duration;

use common::*;
use sub_injector::{
    cache::LinksCache,
    links::{TtlPolicy, MAX_TTL},
};

/// A policy with no lower bound on the TTL, so a test can watch an interval expire instead of
/// waiting out the 30-second production minimum.
fn fast_policy(default: Duration) -> TtlPolicy {
    TtlPolicy { default, min: Duration::ZERO, max: MAX_TTL, respect_headers: true }
}

fn cache(default_ttl: Duration, max_stale: Duration) -> LinksCache {
    LinksCache::with_policy(fast_policy(default_ttl), max_stale)
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

async fn collect(cache: &LinksCache, sources: &[&str]) -> Vec<String> {
    let sources: Vec<String> = sources.iter().map(|s| s.to_string()).collect();
    cache.collect(&sources, &client()).await
}

#[tokio::test]
async fn a_url_source_is_fetched_once_within_its_ttl() {
    let source = MockSource::start("vless://A@1.1.1.1:443#node").await;
    let cache = cache(Duration::from_secs(60), Duration::from_secs(60));

    for _ in 0..3 {
        assert_eq!(collect(&cache, &[&source.url]).await.len(), 1);
    }
    assert_eq!(source.hits(), 1);
}

#[tokio::test]
async fn a_url_source_is_refetched_once_its_ttl_expires() {
    let source = MockSource::start("vless://A@1.1.1.1:443#first").await;
    let cache = cache(Duration::from_millis(50), Duration::from_secs(60));

    assert_eq!(collect(&cache, &[&source.url]).await, vec!["vless://A@1.1.1.1:443#first"]);
    source.set_body("vless://A@1.1.1.1:443#second");
    tokio::time::sleep(Duration::from_millis(80)).await;

    assert_eq!(collect(&cache, &[&source.url]).await, vec!["vless://A@1.1.1.1:443#second"]);
    assert_eq!(source.hits(), 2);
}

#[tokio::test]
async fn the_announced_interval_overrides_the_configured_default() {
    let source = MockSource::start("vless://A@1.1.1.1:443#node").await;
    // The source says "refresh me every hour", so the 50 ms default must not apply.
    source.set_header("profile-update-interval", "1");
    let cache = cache(Duration::from_millis(50), Duration::from_secs(60));

    collect(&cache, &[&source.url]).await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    collect(&cache, &[&source.url]).await;

    assert_eq!(source.hits(), 1, "profile-update-interval: 1 means one hour, not one second");
}

#[tokio::test]
async fn a_not_modified_response_keeps_the_cached_links() {
    let source = MockSource::start("vless://A@1.1.1.1:443#node").await;
    source.set_etag("\"v1\"");
    let cache = cache(Duration::from_millis(50), Duration::from_secs(60));

    assert_eq!(collect(&cache, &[&source.url]).await.len(), 1);
    tokio::time::sleep(Duration::from_millis(80)).await;

    // The body is gone, but the source answers 304 to the conditional request, so the links
    // must survive.
    source.set_body("");
    let links = collect(&cache, &[&source.url]).await;
    assert_eq!(links, vec!["vless://A@1.1.1.1:443#node"]);
    assert_eq!(source.hits(), 2, "the revalidation is a real request");
}

#[tokio::test]
async fn a_failed_refresh_serves_the_last_good_links() {
    let source = MockSource::start("vless://A@1.1.1.1:443#node").await;
    let cache = cache(Duration::from_millis(50), Duration::from_secs(60));

    assert_eq!(collect(&cache, &[&source.url]).await.len(), 1);
    source.set_status(500);
    tokio::time::sleep(Duration::from_millis(80)).await;

    let links = collect(&cache, &[&source.url]).await;
    assert_eq!(links, vec!["vless://A@1.1.1.1:443#node"], "a source outage must not strip the nodes");
}

#[tokio::test]
async fn an_invalid_response_falls_back_to_the_cached_links() {
    let source = MockSource::start("vless://A@1.1.1.1:443#node").await;
    let cache = cache(Duration::from_millis(50), Duration::from_secs(60));
    collect(&cache, &[&source.url]).await;

    // 200 OK, but the body is a captive-portal page rather than a list of links.
    source.set_body("<!DOCTYPE html><html>login here</html>");
    tokio::time::sleep(Duration::from_millis(80)).await;

    assert_eq!(collect(&cache, &[&source.url]).await, vec!["vless://A@1.1.1.1:443#node"]);
}

#[tokio::test]
async fn one_bad_line_rejects_a_whole_remote_source() {
    let source = MockSource::start("vless://A@1.1.1.1:443#node").await;
    let cache = cache(Duration::from_millis(50), Duration::from_secs(60));
    collect(&cache, &[&source.url]).await;

    source.set_body("vless://A@1.1.1.1:443#node\n<html>truncated");
    tokio::time::sleep(Duration::from_millis(80)).await;

    assert_eq!(
        collect(&cache, &[&source.url]).await,
        vec!["vless://A@1.1.1.1:443#node"],
        "a partially valid remote body is corrupt, so the cached answer stands"
    );
}

#[tokio::test]
async fn stale_links_are_dropped_once_the_window_closes() {
    let source = MockSource::start("vless://A@1.1.1.1:443#node").await;
    let cache = cache(Duration::from_millis(20), Duration::from_millis(30));

    assert_eq!(collect(&cache, &[&source.url]).await.len(), 1);
    source.set_status(500);
    tokio::time::sleep(Duration::from_millis(150)).await;

    assert!(
        collect(&cache, &[&source.url]).await.is_empty(),
        "past the stale window the source is dropped rather than served forever"
    );
}

#[tokio::test]
async fn a_file_source_is_reread_when_it_changes() {
    let path = write_temp_file("vless://A@1.1.1.1:443#first");
    let cache = cache(Duration::from_secs(60), Duration::from_secs(60));

    assert_eq!(collect(&cache, &[&path]).await, vec!["vless://A@1.1.1.1:443#first"]);

    // Editing the file takes effect on the next request — files are revalidated by mtime and
    // size, not by the refresh interval.
    tokio::time::sleep(Duration::from_millis(20)).await;
    std::fs::write(&path, "vless://A@1.1.1.1:443#second-and-longer").unwrap();

    assert_eq!(collect(&cache, &[&path]).await, vec!["vless://A@1.1.1.1:443#second-and-longer"]);
}

#[tokio::test]
async fn a_file_source_keeps_its_valid_lines() {
    let path = write_temp_file("vless://A@1.1.1.1:443#good\noops-a-typo\nss://B@2.2.2.2:8388#also-good");
    let cache = cache(Duration::from_secs(60), Duration::from_secs(60));

    let links = collect(&cache, &[&path]).await;
    assert_eq!(links.len(), 2, "a typo drops its own line, not the whole file");
}

#[tokio::test]
async fn a_deleted_file_serves_stale_then_drops() {
    let path = write_temp_file("vless://A@1.1.1.1:443#node");
    let cache = cache(Duration::from_secs(60), Duration::from_millis(50));

    assert_eq!(collect(&cache, &[&path]).await.len(), 1);
    std::fs::remove_file(&path).unwrap();

    assert_eq!(collect(&cache, &[&path]).await.len(), 1, "briefly missing is not a reason to drop nodes");
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(collect(&cache, &[&path]).await.is_empty(), "gone for good means gone from the response");
}

#[tokio::test]
async fn sources_are_merged_in_order_without_duplicates() {
    let shared = "vless://SHARED@9.9.9.9:443#shared";
    let first = write_temp_file(&format!("vless://A@1.1.1.1:443#a\n{shared}"));
    let second = write_temp_file(&format!("{shared}\nvless://B@2.2.2.2:443#b"));
    let cache = cache(Duration::from_secs(60), Duration::from_secs(60));

    let links = collect(&cache, &[&first, &second]).await;
    assert_eq!(
        links,
        vec![
            "vless://A@1.1.1.1:443#a".to_string(),
            shared.to_string(),
            "vless://B@2.2.2.2:443#b".to_string(),
        ]
    );
}

#[tokio::test]
async fn concurrent_requests_for_one_source_cause_one_fetch() {
    let source = MockSource::start("vless://A@1.1.1.1:443#node").await;
    let cache = std::sync::Arc::new(cache(Duration::from_secs(60), Duration::from_secs(60)));

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let cache = cache.clone();
        let url = source.url.clone();
        tasks.push(tokio::spawn(async move {
            cache.collect(&[url], &reqwest::Client::new()).await
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().len(), 1);
    }
    assert_eq!(source.hits(), 1, "a cold cache under load must not stampede the source");
}
