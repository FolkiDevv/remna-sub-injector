//! Remnawave subscription injector: a reverse proxy that appends extra proxy links to a
//! subscription response without touching the upstream panel.

pub mod cache;
pub mod config;
pub mod links;
pub mod proxy;
pub mod source_headers;
pub mod subscription;

/// Neither an upstream response nor a links source may be larger than this.
pub const MAX_BODY_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

pub use proxy::{build_app, AppState};
