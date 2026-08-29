//! Caching of link sources.
//!
//! Without it every client refresh re-read every source: a blocking file read per request, and a
//! full HTTP fetch of somebody else's subscription per request. Each source is refreshed on its
//! own schedule instead, and keeps serving its last good answer for a while when a refresh fails,
//! so a source being down does not quietly strip the extra nodes from a client's subscription.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use crate::{
    links::{
        parse_links_payload, source_kind, source_label, LinksError, SourceKind, TtlPolicy,
    },
    MAX_BODY_SIZE,
};

/// What a source contributed to this response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceOutcome {
    /// Read or fetched now, or still within its refresh interval.
    Fresh(Vec<String>),
    /// The refresh failed, but the previous answer is still inside the stale window.
    Stale(Vec<String>),
    /// Nothing usable — the source is left out of this response.
    Failed,
}

impl SourceOutcome {
    fn links(&self) -> &[String] {
        match self {
            Self::Fresh(links) | Self::Stale(links) => links,
            Self::Failed => &[],
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Validator {
    File { mtime: Option<SystemTime>, len: u64 },
    Http { etag: Option<String>, last_modified: Option<String> },
}

struct Entry {
    links: Vec<String>,
    stored_at: Instant,
    /// How long `links` stays fresh. Zero for files, whose freshness is decided by the file's
    /// own mtime rather than by elapsed time.
    ttl: Duration,
    validator: Validator,
}

type Slot = Arc<tokio::sync::Mutex<Option<Entry>>>;

pub struct LinksCache {
    /// One slot per source. The map lock is held only long enough to hand out a slot; the slot
    /// lock is held across the refresh, so requests for different sources never wait on each
    /// other and concurrent requests for the same source cause one refresh, not a stampede.
    slots: Mutex<HashMap<String, Slot>>,
    ttl_policy: TtlPolicy,
    max_stale: Duration,
}

impl LinksCache {
    pub fn new(default_ttl: Duration, max_stale: Duration, respect_headers: bool) -> Self {
        Self::with_policy(TtlPolicy::new(default_ttl, respect_headers), max_stale)
    }

    pub fn with_policy(ttl_policy: TtlPolicy, max_stale: Duration) -> Self {
        Self { slots: Mutex::new(HashMap::new()), ttl_policy, max_stale }
    }

    /// Every link a rule contributes, in the order its sources are configured, without
    /// duplicates. Sources that cannot be read at all are left out.
    pub async fn collect(&self, sources: &[String], client: &reqwest::Client) -> Vec<String> {
        let mut links: Vec<String> = Vec::new();
        let (mut fresh, mut stale, mut failed) = (0, 0, 0);

        for source in sources {
            let outcome = self.get(source, client).await;
            match outcome {
                SourceOutcome::Fresh(_) => fresh += 1,
                SourceOutcome::Stale(_) => stale += 1,
                SourceOutcome::Failed => failed += 1,
            }
            for link in outcome.links() {
                // The same node listed by two subscriptions must not reach the client twice.
                if !links.iter().any(|seen| seen == link) {
                    links.push(link.clone());
                }
            }
        }

        if stale > 0 || failed > 0 {
            eprintln!(
                "[sub-injector] links: {} from {fresh} fresh, {stale} stale, {failed} unavailable source(s)",
                links.len()
            );
        }
        links
    }

    async fn get(&self, source: &str, client: &reqwest::Client) -> SourceOutcome {
        let slot = self.slot(source);
        let mut entry = slot.lock().await;
        match source_kind(source) {
            SourceKind::File => self.refresh_file(source, &mut entry).await,
            SourceKind::Url => self.refresh_url(source, client, &mut entry).await,
        }
    }

    fn slot(&self, source: &str) -> Slot {
        let mut slots = self.slots.lock().expect("links cache mutex poisoned");
        slots.entry(source.to_string()).or_default().clone()
    }

    /// A file is cheap to stat, so it is revalidated by mtime and size rather than by a timer —
    /// editing the file takes effect on the next request instead of after the TTL.
    async fn refresh_file(&self, source: &str, entry: &mut Option<Entry>) -> SourceOutcome {
        let metadata = match tokio::fs::metadata(source).await {
            Ok(metadata) => Some(metadata),
            Err(e) => {
                eprintln!("[sub-injector] cannot stat links source {source}: {e}");
                None
            }
        };

        if let Some(metadata) = &metadata {
            let current = Validator::File { mtime: metadata.modified().ok(), len: metadata.len() };
            // An unknown mtime cannot prove the file is unchanged, so re-read instead.
            let known_mtime = matches!(current, Validator::File { mtime: Some(_), .. });
            if let Some(entry) = entry.as_ref() {
                if known_mtime && entry.validator == current {
                    return SourceOutcome::Fresh(entry.links.clone());
                }
            }

            match tokio::fs::read_to_string(source).await {
                Ok(text) => match parse_links_payload(&text, SourceKind::File) {
                    Ok(parsed) => {
                        if parsed.skipped > 0 {
                            // Not fatal for a hand-written file: a typo drops its own line and
                            // the rest of the nodes still reach clients.
                            eprintln!(
                                "[sub-injector] links source {source}: skipped {} line(s) that are not proxy links",
                                parsed.skipped
                            );
                        }
                        let links = parsed.links;
                        *entry = Some(Entry {
                            links: links.clone(),
                            stored_at: Instant::now(),
                            ttl: Duration::ZERO,
                            validator: current,
                        });
                        return SourceOutcome::Fresh(links);
                    }
                    Err(e) => eprintln!("[sub-injector] links source {source} rejected: {e}"),
                },
                Err(e) => eprintln!("[sub-injector] cannot read links source {source}: {e}"),
            }
        }
        self.stale_or_failed(source, entry)
    }

    async fn refresh_url(
        &self,
        source: &str,
        client: &reqwest::Client,
        entry: &mut Option<Entry>,
    ) -> SourceOutcome {
        let label = source_label(source);
        if let Some(cached) = entry.as_ref() {
            if cached.stored_at.elapsed() < cached.ttl {
                return SourceOutcome::Fresh(cached.links.clone());
            }
        }

        let mut request = client.get(source);
        if let Some(Entry { validator: Validator::Http { etag, last_modified }, .. }) = entry.as_ref() {
            if let Some(etag) = etag {
                request = request.header("if-none-match", etag);
            }
            if let Some(last_modified) = last_modified {
                request = request.header("if-modified-since", last_modified);
            }
        }

        match self.fetch(request).await {
            Ok(Fetched::NotModified { ttl }) => {
                let cached = entry.as_mut().expect("304 only follows a conditional request");
                cached.stored_at = Instant::now();
                cached.ttl = ttl;
                SourceOutcome::Fresh(cached.links.clone())
            }
            Ok(Fetched::Body { links, ttl, validator }) => {
                *entry = Some(Entry { links: links.clone(), stored_at: Instant::now(), ttl, validator });
                SourceOutcome::Fresh(links)
            }
            Err(e) => {
                eprintln!("[sub-injector] links source {label} failed: {e}");
                self.stale_or_failed(&label, entry)
            }
        }
    }

    async fn fetch(&self, request: reqwest::RequestBuilder) -> Result<Fetched, String> {
        let response = request.send().await.map_err(|e| e.to_string())?;
        let status = response.status();
        let headers = response.headers().clone();
        let ttl = self.ttl_policy.for_headers(&headers);

        if status == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(Fetched::NotModified { ttl });
        }
        if !status.is_success() {
            return Err(format!("HTTP {}", status.as_u16()));
        }
        if response.content_length().unwrap_or(0) > MAX_BODY_SIZE {
            return Err("response too large".to_string());
        }
        let text = response.text().await.map_err(|e| e.to_string())?;
        if text.len() as u64 > MAX_BODY_SIZE {
            return Err("response too large".to_string());
        }

        let parsed = parse_links_payload(&text, SourceKind::Url).map_err(|e: LinksError| e.to_string())?;
        Ok(Fetched::Body {
            links: parsed.links,
            ttl,
            validator: Validator::Http {
                etag: header_owned(&headers, "etag"),
                last_modified: header_owned(&headers, "last-modified"),
            },
        })
    }

    /// A source that just failed keeps serving its last good answer for `max_stale` past its
    /// refresh interval. Beyond that the links are too old to stand behind, and the source is
    /// dropped from the response rather than served indefinitely.
    fn stale_or_failed(&self, label: &str, entry: &Option<Entry>) -> SourceOutcome {
        match entry.as_ref() {
            Some(cached) if cached.stored_at.elapsed() <= cached.ttl + self.max_stale => {
                eprintln!(
                    "[sub-injector] links source {label}: serving cached links from {}s ago",
                    cached.stored_at.elapsed().as_secs()
                );
                SourceOutcome::Stale(cached.links.clone())
            }
            Some(_) => {
                eprintln!("[sub-injector] links source {label}: cached links too old, dropping source");
                SourceOutcome::Failed
            }
            None => SourceOutcome::Failed,
        }
    }
}

enum Fetched {
    NotModified { ttl: Duration },
    Body { links: Vec<String>, ttl: Duration, validator: Validator },
}

fn header_owned(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
}
