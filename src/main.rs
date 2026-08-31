use std::{env, sync::Arc};

use sub_injector::{
    build_app,
    cache::LinksCache,
    config::load_config,
    source_headers::SourceHeaders,
    AppState,
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let config_path = env::var("CONFIG_FILE").unwrap_or_else(|_| "config.toml".to_string());
    let file_cfg = load_config(&config_path);
    let bind_addr = file_cfg.bind_addr.clone().unwrap_or_else(|| "0.0.0.0:3020".to_string());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("Failed to build HTTP client");

    // A source is usually another panel, and a panel answers by who is asking: the format it
    // serves is chosen by the User-Agent, so the injector asks as one steady client that panels
    // answer with a plain link list. The hwid is derived from the upstream URL, which keeps it
    // the same across restarts instead of claiming a new device on every one.
    let source_headers = SourceHeaders::from_config(&file_cfg.upstream_url, &file_cfg.source_headers);
    let links_cache = LinksCache::new(
        file_cfg.cache_ttl(),
        file_cfg.cache_max_stale(),
        file_cfg.cache_respect_headers,
    )
    .with_source_headers(source_headers.clone());

    let cfg = Arc::new(AppState {
        upstream: file_cfg.upstream_url,
        bind_addr: bind_addr.clone(),
        injections: file_cfg.injections,
        client,
        links_cache,
    });

    let app = build_app(cfg);

    let listener = TcpListener::bind(&bind_addr)
        .await
        .expect("Failed to bind");

    if !source_headers.is_empty() {
        // Names only: x-hwid is what identifies this deployment to a source.
        println!("link sources are fetched with: {}", source_headers.names().join(", "));
    }
    println!("sub-injector v{} listening on {bind_addr}", env!("CARGO_PKG_VERSION"));
    axum::serve(listener, app).await.unwrap();
}
