# remna-sub-injector

**Remnawave Subscription Injector Proxy** — adds extra protocols (Hysteria2, TrustTunnel, SOCKS, MTProto, etc.) into a single [Remnawave](https://docs.rw) subscription without modifying the upstream server.

## What it does

When a VPN client fetches a subscription list, the injector:

1. Forwards the request to the upstream subscription server unchanged
2. Checks the request headers (e.g. `User-Agent`) against configured rules
3. If a rule matches and the response is a base64-encoded subscription list — decodes it, appends the configured extra links, and re-encodes it before sending back to the client
4. If no rule matches, or the response is a YAML/JSON config — passes it through untouched
5. If the response is a service message rather than a working subscription — passes it through untouched

This allows injecting additional links (e.g. your own Hysteria2 or VLESS nodes) into subscription lists without modifying the upstream server, and doing so selectively per client app.

## How injection works

- The response body is expected to be a base64-encoded newline-separated list of proxy URIs
- The injector base64-decodes the body, appends the extra links, and re-encodes
- YAML and JSON content types are never modified (Clash/Sing-Box config files)
- Injection rules are evaluated in order; the first matching rule wins
- A rule may take its links from several sources at once, merged in the order they are listed;
  a link that appears in more than one source is injected once
- Each source is cached, so a client refreshing its subscription does not cause a fetch of every
  source (see [Caching](#caching))
- If every source of the matching rule is unreachable or empty, the response is passed through
  unchanged

## Service messages

When a user is deactivated, their subscription has expired, or they have used up their
traffic, Remnawave still answers with a base64 list — but one made of placeholder entries
carrying the status as their remark. Appending extra links to such a response would hand a
blocked user working nodes, so the injector detects these responses and proxies them
untouched.

Detection uses two signals that Remnawave generates itself, so nothing needs configuring
and no panel setting can silently disable them:

- **Placeholder endpoints** — every entry in the body points at a non-routable host
  (`0.0.0.0`, `127.0.0.1`, `::`, `::1`, `localhost`). This is the only signal that catches a
  deactivated user whose expiry date and traffic budget are still fine.
- **The `subscription-userinfo` response header** — `expire` is non-zero and in the past, or
  `total` is non-zero and `upload + download` has reached it. (`expire = 0` means "never
  expires" and `total = 0` means "unlimited traffic"; neither counts as a service state.)

The skip is deliberately conservative: an entry whose host cannot be read — a `vmess://`
link, for instance, which hides its endpoint inside a base64 payload — counts as a real
node, so an unusual body is still injected rather than silently skipped.

The reason for each skip is written to the log, without the header value itself:

```
[sub-injector] skipping injection: service message (service hosts)
[sub-injector] skipping injection: service message (userinfo: expired)
[sub-injector] skipping injection: service message (userinfo: traffic limit)
```

## Security notes

- **Close the port from the public internet.** The injector has no built-in authentication — security relies entirely on the subscription token in the URL being secret. Make sure port 3020 is not reachable from the outside (firewall rule or a private Docker network).
- **No TLS on the injector itself.** Traffic between the client and the injector is plain HTTP, so tokens and links are transmitted in cleartext. Place a reverse proxy (nginx, Caddy, etc.) with a TLS certificate in front of the injector when clients connect over the internet.
- **A links source can be a secret.** When a source is another panel's subscription link, its path *is* the credential guarding it. The injector never writes that path to the log — a remote source appears there as its scheme and host only (`https://panel.example.com/...`), the same way incoming request paths are already truncated. Local file paths are logged whole; they are not secrets.

## Installation

### Option 1 — Docker Compose (recommended)

The image is published to the GitHub Container Registry and built for both
`linux/amd64` and `linux/arm64`:

```
ghcr.io/folkidevv/remna-sub-injector:latest
```

Tags follow the release version: `latest`, `1.2.3`, `1.2`, `1`.

The container runs as an unprivileged user (UID/GID `10001`) and never writes to
disk, so it can run fully read-only. Make sure `config.toml` and the files under
`data/` are readable by that UID on the host — the usual `644` permissions are
fine.

**Step 1.** Clone the repository:

```bash
git clone https://github.com/itwormz/remna-sub-injector /opt/remna-sub-injector
cd /opt/remna-sub-injector
```

**Step 2.** Create the config:

```bash
cp config.toml.example config.toml
```

Edit `config.toml` before starting.

**Step 3.** Prepare your extra links.

Each injection rule in `config.toml` has a `links_source` field — the injector reads proxy URIs from it and appends them to every matching subscription response. It takes one source or a list of them:

- **Local file** — create the file and put one proxy URI per line:
  ```bash
  mkdir -p data
  nano data/hysteria2-links.txt
  ```
- **Remote URL** — an `https://` URL returning the same one-URI-per-line format.
- **Another subscription** — an `https://` subscription link. Those serve a base64 list; the
  injector detects that and decodes it, so nodes from another panel can be merged in as they are.

See [Links source format](#links-source-format) for details.

**Step 4.** Create `docker-compose.yml`:

```bash
cp docker-compose.yml.example docker-compose.yml
```

**Step 5.** Start:

```bash
docker compose up -d
```

### Option 2 — Binary + systemd

Pre-built binaries are published in [GitHub Releases](../../releases):

| File | Architecture |
|---|---|
| `sub-injector-linux-x86_64` | x86_64 (most servers) |
| `sub-injector-linux-aarch64` | ARM64 (Raspberry Pi, AWS Graviton, etc.) |

**Step 1.** Download the binary:

```bash
ARCH=$(uname -m)
case $ARCH in
  x86_64)  BINARY="sub-injector-linux-x86_64" ;;
  aarch64) BINARY="sub-injector-linux-aarch64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac
curl -L https://github.com/itwormz/remna-sub-injector/releases/latest/download/${BINARY} \
  -o /usr/local/bin/sub-injector
chmod +x /usr/local/bin/sub-injector
```

To install a specific version, replace `latest/download` with `download/v0.1.0` in the URL.

**Step 2.** Create the config:

```bash
mkdir -p /opt/remna-sub-injector
curl -L https://github.com/itwormz/remna-sub-injector/releases/latest/download/config.toml.example \
  -o /opt/remna-sub-injector/config.toml
```

Edit `/opt/remna-sub-injector/config.toml` before starting.

**Step 3.** Create the service file:

```bash
cat > /etc/systemd/system/sub-injector.service << 'EOF'
[Unit]
Description=remna-sub-injector
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sub-injector
Environment=CONFIG_FILE=/opt/remna-sub-injector/config.toml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
```

**Step 4.** Enable and start:

```bash
systemctl daemon-reload
systemctl enable --now sub-injector
systemctl status sub-injector
```

View logs:

```bash
journalctl -u sub-injector -f
```

## Configuration

The injector reads a TOML config file. By default it looks for `config.toml` in the working directory. Override with the `CONFIG_FILE` environment variable.

### Config reference

| Key | Type | Required | Default | Description |
|---|---|---|---|---|
| `upstream_url` | string | yes | — | Base URL of the upstream subscription server |
| `bind_addr` | string | no | `0.0.0.0:3020` | Address and port to listen on |
| `cache_ttl` | integer | no | `300` | Seconds a links source may be reused when it does not announce an interval of its own |
| `cache_max_stale` | integer | no | `3600` | Seconds a source may keep serving its last good answer after a failed refresh |
| `cache_respect_headers` | bool | no | `true` | `false` ignores what a source announces and always uses `cache_ttl` |
| `injections` | array | yes | — | List of injection rules (see below) |

Each `[[injections]]` rule:

| Key | Type | Description |
|---|---|---|
| `header` | string | Request header name to match against (case-insensitive) |
| `contains` | array of strings | List of substrings — rule matches if the header value contains **any** of them (case-insensitive) |
| `links_source` | string **or** array of strings | Where the extra links come from: a local file path, an `http(s)://` URL, or an `http(s)://` subscription link. Several sources are merged in the order given |

### Example config

```toml
upstream_url = "http://upstream:2096"
bind_addr = "0.0.0.0:3020"

[[injections]]
header = "User-Agent"
contains = ["hiddify", "happ", "nekobox", "nekoray", "sing-box", "v2rayng"]
links_source = "/data/hysteria2-links.txt"

[[injections]]
header = "User-Agent"
contains = ["clash.meta", "mihomo"]
links_source = "/data/clash-links.txt"

# Several sources on one rule:
# [[injections]]
# header = "User-Agent"
# contains = ["hiddify"]
# links_source = [
#   "/data/hysteria2-links.txt",
#   "https://example.com/my-extra-links.txt",
#   "https://another-panel.example.com/sub/YOUR-TOKEN",
# ]
```

## Links source format

A links source contains one proxy URI per line:

```
hysteria2://password@1.2.3.4:443?obfs=salamander&obfs-password=secret#My-Node-1
vless://uuid@5.6.7.8:443?security=tls#My-Node-2
ss://base64encodedinfo@9.10.11.12:8388#My-Node-3
```

Blank lines and leading/trailing whitespace are stripped automatically.

A source may also be a whole **base64 subscription** — the format Remnawave, Marzban and the
others serve. That shape is detected, not configured: if the payload has no readable URI in it,
it is decoded as base64 and read again. So a subscription link from another panel can be listed
as a source directly, and its nodes are merged into the response.

### Validation

Everything a source returns is checked to be a list of proxy URIs (`scheme://…`) before any of it
reaches a client, which keeps an HTML error page, a captive portal or a truncated body out of the
subscription. What happens to a source that is only partly readable depends on where it came from:

- **A local file** is hand-written, so an unreadable line is treated as a typo: that line is
  dropped, a warning naming the count goes to the log, and the remaining nodes are injected.
- **A remote source** is machine-generated, so a line that is not a proxy URI means the response
  is corrupt rather than mistyped — the whole source is rejected and its cached links are used
  instead (see [Caching](#caching)).

A source whose own subscription is expired, disabled or out of traffic is rejected too: its body
is placeholder entries on `0.0.0.0`, detected exactly as described under
[Service messages](#service-messages), and injecting those would hand clients dead nodes.

## Caching

Without caching every client refresh would re-read every source — a file read and a full HTTP
fetch of somebody else's subscription per request. Each source is refreshed on its own schedule
instead.

**Local files** are not on a timer at all. They are revalidated by modification time and size,
which is cheap, so editing a links file takes effect on the very next request.

**Remote sources** are refreshed on an interval taken from the first of these that applies:

1. **`profile-update-interval`** — the response header from the
   [XTLS subscription standard](https://github.com/XTLS/Xray-core/discussions/4877), in **hours**.
   This is the signal VPN clients themselves follow, and Remnawave sends it (its
   `SUB_UPDATE_INTERVAL`, 12 hours by default), as do Marzban, Marzneshin and Hiddify Manager.
2. **`Cache-Control: max-age` / `s-maxage`** — not part of the subscription standard, but it is
   what nginx or a CDN sends when a plain-text list is served as a static file. `no-cache` and
   `no-store` are read as "as often as allowed" rather than "every request".
3. **`cache_ttl`** from the config, 300 seconds by default.

The result is clamped to between 30 seconds and 24 hours, so neither an over-eager source nor a
stray `profile-update-interval: 8760` can take over. Set `cache_respect_headers = false` to skip
steps 1 and 2 and always use `cache_ttl`. If a source sends an `ETag` or `Last-Modified`, the
refresh is conditional and a `304` just restarts the interval.

`Expires` is not supported — the subscription standard does not use it, and parsing HTTP dates
would mean another dependency.

When a refresh fails — the source is down, answers non-2xx, or returns something that does not
validate — its last good answer keeps being served for `cache_max_stale` (an hour by default) past
the refresh interval. Beyond that the links are too old to stand behind and the source is dropped
from the response. Either way the other sources of the rule are unaffected, and the log says which
source went stale. This matters because the alternative is silent: before caching, a source being
down meant the client simply got a subscription without your extra nodes.

## Building from source

Native binary (x86_64):

```bash
cargo build --release
```

ARM64 musl (for Alpine / aarch64 servers):

Install the cross-compilation tool once:

```bash
cargo install cross
```

Then build:

```bash
cross build --release --target aarch64-unknown-linux-musl
```

Output: `target/aarch64-unknown-linux-musl/release/sub-injector`

### Docker image

The `Dockerfile` is multi-stage — it compiles the binary itself, so no
pre-built artifact is needed:

```bash
docker build -t sub-injector .
```

The result is a `scratch`-based image containing only the statically linked
binary (a few megabytes).
