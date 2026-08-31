//! The TOML config file and its defaults.

use std::{collections::HashMap, fs, time::Duration};

use serde::{Deserialize, Deserializer};

use crate::{
    source_headers::{is_reserved, MAX_HWID_LEN},
    subscription::is_proxy_uri,
};

/// Used when a source does not announce a refresh interval of its own.
pub const DEFAULT_CACHE_TTL_SECS: u64 = 300;
/// How long a source may keep serving its last good value after a failed refresh.
pub const DEFAULT_CACHE_MAX_STALE_SECS: u64 = 3600;

#[derive(Debug, serde::Deserialize)]
pub struct FileConfig {
    pub upstream_url: String,
    pub bind_addr: Option<String>,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,
    #[serde(default = "default_cache_max_stale")]
    pub cache_max_stale: u64,
    #[serde(default = "default_respect_headers")]
    pub cache_respect_headers: bool,
    /// Overrides for the headers sent when a links source is fetched over HTTP. Absent means the
    /// defaults; an empty value drops that header. Setting `user-agent` here also turns off the
    /// format fallback — see [`crate::source_headers`].
    #[serde(default)]
    pub source_headers: HashMap<String, String>,
    pub injections: Vec<InjectionRule>,
}

fn default_cache_ttl() -> u64 {
    DEFAULT_CACHE_TTL_SECS
}

fn default_cache_max_stale() -> u64 {
    DEFAULT_CACHE_MAX_STALE_SECS
}

fn default_respect_headers() -> bool {
    true
}

impl FileConfig {
    pub fn cache_ttl(&self) -> Duration {
        Duration::from_secs(self.cache_ttl)
    }

    pub fn cache_max_stale(&self) -> Duration {
        Duration::from_secs(self.cache_max_stale)
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct InjectionRule {
    pub header: String,
    pub contains: Vec<String>,
    /// One source or several, merged in the order given. Accepts a bare string as well as an
    /// array, so configs written for the single-source version keep working untouched.
    #[serde(deserialize_with = "one_or_many")]
    pub links_source: Vec<String>,
}

fn one_or_many<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(v) => v,
    })
}

pub fn load_config(path: &str) -> FileConfig {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Cannot read config file {path}: {e}"));
    let config: FileConfig = toml::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid config file {path}: {e}"));
    validate(&config)
        .unwrap_or_else(|e| panic!("Invalid config file {path}: {e}"));
    if let Some(hwid) = config.source_headers.iter().find(|(name, _)| name.eq_ignore_ascii_case("x-hwid")) {
        if hwid.1.len() > MAX_HWID_LEN {
            eprintln!(
                "[sub-injector] warning: source_headers x-hwid is {} characters; panels usually reject anything over {MAX_HWID_LEN}",
                hwid.1.len()
            );
        }
    }
    config
}

/// Catches at startup what would otherwise only show up as a rule that silently injects nothing.
fn validate(config: &FileConfig) -> Result<(), String> {
    for (name, value) in &config.source_headers {
        if reqwest::header::HeaderName::try_from(name.as_str()).is_err() {
            return Err(format!("source_headers: {name:?} is not a valid header name"));
        }
        if reqwest::header::HeaderValue::try_from(value.as_str()).is_err() {
            return Err(format!("source_headers ({name}): the value is not valid for a header"));
        }
        // Set here they would either be overwritten by the fetch itself or break it outright.
        if is_reserved(name) {
            return Err(format!("source_headers: {name} is set by the injector and cannot be configured"));
        }
    }

    for (i, rule) in config.injections.iter().enumerate() {
        if rule.links_source.is_empty() {
            return Err(format!("injections[{i}] ({}): links_source is empty", rule.header));
        }
        for source in &rule.links_source {
            if source.trim().is_empty() {
                return Err(format!("injections[{i}] ({}): links_source has a blank entry", rule.header));
            }
            // A source is a local path or an http(s) URL; a proxy URI here means someone put the
            // node itself where its source belongs.
            if is_proxy_uri(source) && !source.starts_with("http://") && !source.starts_with("https://") {
                return Err(format!(
                    "injections[{i}] ({}): links_source must be a file path or an http(s) URL, not a proxy link",
                    rule.header
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp_file(content: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
        let path = std::env::temp_dir().join(format!("test-config-{}-{suffix}.toml", std::process::id()));
        fs::write(&path, content).unwrap();
        path.to_str().unwrap().to_string()
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
        // A single string still parses — configs from the single-source version keep working.
        assert_eq!(cfg.injections[0].links_source, vec!["/data/hy2.txt"]);
    }

    #[test]
    fn load_config_parses_multiple_sources() {
        let toml_content = r#"
upstream_url = "http://upstream:2096"

[[injections]]
header = "User-Agent"
contains = ["hiddify"]
links_source = ["/data/hy2.txt", "https://example.com/list.txt", "https://panel.example.com/sub/TOKEN"]
"#;
        let path = write_temp_file(toml_content);
        let cfg = load_config(&path);
        assert_eq!(
            cfg.injections[0].links_source,
            vec!["/data/hy2.txt", "https://example.com/list.txt", "https://panel.example.com/sub/TOKEN"]
        );
    }

    #[test]
    fn cache_settings_have_defaults() {
        let toml_content = r#"
upstream_url = "http://upstream:2096"

[[injections]]
header = "User-Agent"
contains = ["hiddify"]
links_source = "/data/hy2.txt"
"#;
        let cfg = load_config(&write_temp_file(toml_content));
        assert_eq!(cfg.cache_ttl, DEFAULT_CACHE_TTL_SECS);
        assert_eq!(cfg.cache_max_stale, DEFAULT_CACHE_MAX_STALE_SECS);
        assert!(cfg.cache_respect_headers);
    }

    #[test]
    fn cache_settings_are_read_from_the_file() {
        let toml_content = r#"
upstream_url = "http://upstream:2096"
cache_ttl = 60
cache_max_stale = 120
cache_respect_headers = false

[[injections]]
header = "User-Agent"
contains = ["hiddify"]
links_source = "/data/hy2.txt"
"#;
        let cfg = load_config(&write_temp_file(toml_content));
        assert_eq!(cfg.cache_ttl(), Duration::from_secs(60));
        assert_eq!(cfg.cache_max_stale(), Duration::from_secs(120));
        assert!(!cfg.cache_respect_headers);
    }

    #[test]
    #[should_panic(expected = "links_source is empty")]
    fn empty_links_source_is_rejected() {
        let toml_content = r#"
upstream_url = "http://upstream:2096"

[[injections]]
header = "User-Agent"
contains = ["hiddify"]
links_source = []
"#;
        load_config(&write_temp_file(toml_content));
    }

    #[test]
    fn source_headers_are_read_from_the_file() {
        let toml_content = r#"
upstream_url = "http://upstream:2096"

[source_headers]
user-agent = "Happ/9.9.9"
x-hwid = ""

[[injections]]
header = "User-Agent"
contains = ["hiddify"]
links_source = "/data/hy2.txt"
"#;
        let cfg = load_config(&write_temp_file(toml_content));
        assert_eq!(cfg.source_headers.get("user-agent"), Some(&"Happ/9.9.9".to_string()));
        assert_eq!(cfg.source_headers.get("x-hwid"), Some(&String::new()));
    }

    #[test]
    fn source_headers_default_to_empty() {
        let toml_content = r#"
upstream_url = "http://upstream:2096"

[[injections]]
header = "User-Agent"
contains = ["hiddify"]
links_source = "/data/hy2.txt"
"#;
        assert!(load_config(&write_temp_file(toml_content)).source_headers.is_empty());
    }

    #[test]
    #[should_panic(expected = "cannot be configured")]
    fn a_reserved_source_header_is_rejected() {
        let toml_content = r#"
upstream_url = "http://upstream:2096"

[source_headers]
Accept-Encoding = "gzip"

[[injections]]
header = "User-Agent"
contains = ["hiddify"]
links_source = "/data/hy2.txt"
"#;
        load_config(&write_temp_file(toml_content));
    }

    #[test]
    #[should_panic(expected = "not a valid header name")]
    fn a_malformed_source_header_name_is_rejected() {
        let toml_content = r#"
upstream_url = "http://upstream:2096"

[source_headers]
"user agent" = "Happ/1.0"

[[injections]]
header = "User-Agent"
contains = ["hiddify"]
links_source = "/data/hy2.txt"
"#;
        load_config(&write_temp_file(toml_content));
    }

    #[test]
    #[should_panic(expected = "not a proxy link")]
    fn proxy_link_as_a_source_is_rejected() {
        let toml_content = r#"
upstream_url = "http://upstream:2096"

[[injections]]
header = "User-Agent"
contains = ["hiddify"]
links_source = "hysteria2://PASS@10.0.0.1:5350#node"
"#;
        load_config(&write_temp_file(toml_content));
    }
}
