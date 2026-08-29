use std::{env, sync::Arc};

use sub_injector::{
    build_app,
    cache::LinksCache,
    config::load_config,
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

    let links_cache = LinksCache::new(
        file_cfg.cache_ttl(),
        file_cfg.cache_max_stale(),
        file_cfg.cache_respect_headers,
    );

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

    println!("sub-injector v{} listening on {bind_addr}", env!("CARGO_PKG_VERSION"));
    axum::serve(listener, app).await.unwrap();
}
