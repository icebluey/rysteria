# rysteria

A pure-Rust implementation of the [Hysteria 2](https://v2.hysteria.network/) proxy protocol.
Wire-compatible with the official Go implementation.

---

## Overview

Rysteria tunnels TCP and UDP traffic over QUIC, using HTTP/3 for authentication and a
custom frame type (`0x401`) for stream multiplexing. It is feature-complete with Hysteria 2:
port-hopping, Salamander obfuscation, ACL routing, multiple auth backends, masquerade,
traffic statistics, TUN mode, and post-quantum TLS.

**Key properties:**

- QUIC transport via [quinn 0.11](https://github.com/quinn-rs/quinn) (RFC 9000)
- HTTP/3 authentication via [h3 0.0.8](https://github.com/hyperium/h3) (RFC 9114)
- TLS via [rustls 0.23](https://github.com/rustls/rustls) with AWS-LC-RS crypto
- Post-quantum hybrid key exchange (X25519MLKEM768) enabled by default
- Brutal and BBR congestion control
- Wire-compatible with Hysteria 2 Go clients and servers

---

## Installation

### Pre-built binaries

Download from the [Releases](../../releases) page. Binaries are available for:

| Platform | Variants |
|----------|----------|
| Linux (musl, static) | amd64, amd64-avx, arm64, armv7, armv5, mipsle, mipsle-sf, s390x, riscv64, loong64 |
| Linux (gnu, dynamic) | amd64, amd64-avx, 386, arm64, armv7, armv5, mipsle, s390x, riscv64, loong64 |
| Windows | amd64, amd64-avx, arm64, 386 |
| macOS | amd64, arm64 |
| FreeBSD | amd64, arm64 |
| Android | arm64, armv7, 386, amd64 |

### Build from source

```bash
cargo build --release
```

For cross-platform release builds, use the included `hyperbole.py` build script:

```bash
# Build for the native host (auto-detected)
python3 hyperbole.py build

# Build specific platforms via RY_APP_PLATFORMS env var
RY_APP_PLATFORMS="linux/amd64-avx,windows/amd64-avx" python3 hyperbole.py build

# Build all platforms listed in platforms.txt
RY_APP_PLATFORMS=all python3 hyperbole.py build

# Build a debug (non-release) binary
python3 hyperbole.py build --dev

# Show all supported platforms and detected toolchains
python3 hyperbole.py about
```

`platforms.txt` lists all release platforms. Use `RY_APP_PLATFORMS=all` to build all of
them, or set a comma-separated subset, e.g. `RY_APP_PLATFORMS="linux/amd64-musl,windows/amd64"`.

Build requirements: Rust 1.85+, Python 3.8+, `cargo-xwin` (Windows targets), `cross` (Linux cross-compilation, FreeBSD, Android).

---

## Quick Start

### Server

```yaml
# server.yaml
listen: "0.0.0.0:443"

tls:
  cert: "/path/to/server.crt"
  key:  "/path/to/server.key"

auth:
  type: password
  password: "your-password"
```

```toml
# server.toml
listen = "0.0.0.0:443"

[tls]
cert = "/path/to/server.crt"
key = "/path/to/server.key"

[auth]
type = "password"
password = "your-password"
```

```bash
rysteria -c server.yaml server
```

### Client

```yaml
# client.yaml
server: "your-server.example.com:443"
auth: "your-password"

socks5:
  listen: "127.0.0.1:1080"
```

```toml
# client.toml
server = "your-server.example.com:443"
auth = "your-password"

[socks5]
listen = "127.0.0.1:1080"
```

```bash
rysteria -c client.yaml client
# or simply
rysteria -c client.yaml
```

---

## Server Configuration

### Top-level fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen` | string | — | Bind address and port, e.g. `"0.0.0.0:443"` |
| `ignoreClientBandwidth` | bool | `false` | Ignore client-reported RX bandwidth; use server-side congestion control only |
| `speedTest` | bool | `false` | Allow clients to run speed tests against this server |
| `disableUDP` | bool | `false` | Disable UDP relay |
| `udpIdleTimeout` | duration | `"60s"` | Idle timeout for UDP sessions |

### `tls`

```yaml
tls:
  cert: "/path/to/cert.pem"
  key:  "/path/to/key.pem"
  sniGuard: "dns-san"    # disable | dns-san | strict
  clientCA: "/path/to/ca.pem"  # mutual TLS
```

```toml
[tls]
cert = "/path/to/cert.pem"
key = "/path/to/key.pem"
sniGuard = "dns-san"  # disable | dns-san | strict
clientCA = "/path/to/ca.pem"
```

`sniGuard` modes:

| Mode | Behavior |
|------|----------|
| `disable` | Accept any SNI |
| `dns-san` | Reject connections whose SNI does not match any DNS SAN in the certificate (default) |
| `strict` | Reject connections whose SNI does not match any subject name in the certificate (via webpki verification) |

### `obfs`

Salamander obfuscation scrambles QUIC packets with a BLAKE2b-keyed XOR cipher, making
traffic indistinguishable from random bytes.

```yaml
obfs:
  type: salamander
  salamander:
    password: "obfuscation-password"
```

```toml
[obfs]
type = "salamander"

[obfs.salamander]
password = "obfuscation-password"
```

Both client and server must use the same password.

### `quic`

```yaml
quic:
  initStreamReceiveWindow:  8388608   # 8 MiB per stream
  maxStreamReceiveWindow:   8388608
  initConnReceiveWindow:    20971520  # 20 MiB per connection
  maxConnReceiveWindow:     20971520
  maxIdleTimeout:           "30s"
  maxIncomingStreams:        0         # 0 = default (1024)
  disablePathMTUDiscovery:  false
```

```toml
[quic]
initStreamReceiveWindow = 8388608
maxStreamReceiveWindow = 8388608
initConnReceiveWindow = 20971520
maxConnReceiveWindow = 20971520
maxIdleTimeout = "30s"
maxIncomingStreams = 0
disablePathMTUDiscovery = false
```

### `auth`

| Type | Description |
|------|-------------|
| `password` | Single shared password |
| `userpass` | Per-user `username: password` map (case-insensitive usernames) |
| `http` | Webhook: POST JSON `{addr, auth, tx}` → `{ok, id}` |
| `command` | External command: `<cmd> <addr> <auth> <tx>` (exit 0 = success) |

```yaml
# Single password
auth:
  type: password
  password: "secret"

# Per-user passwords
auth:
  type: userpass
  userpass:
    alice: "pass1"
    bob:   "pass2"

# HTTP webhook
auth:
  type: http
  http:
    url: "https://auth.example.com/verify"
    insecure: false

# External command
auth:
  type: command
  command: "/usr/local/bin/auth-hook"
```

```toml
# Single password
[auth]
type = "password"
password = "secret"
```

```toml
# Per-user passwords
[auth]
type = "userpass"

[auth.userpass]
alice = "pass1"
bob = "pass2"
```

```toml
# HTTP webhook
[auth]
type = "http"

[auth.http]
url = "https://auth.example.com/verify"
insecure = false
```

```toml
# External command
[auth]
type = "command"
command = "/usr/local/bin/auth-hook"
```

### `bandwidth`

Server-side bandwidth limits (applies to all clients collectively):

```yaml
bandwidth:
  up:   "1 Gbps"
  down: "1 Gbps"
```

```toml
[bandwidth]
up = "1 Gbps"
down = "1 Gbps"
```

Units (decimal SI, case-insensitive): `bps`/`b`, `kbps`/`k`/`kb`, `mbps`/`m`/`mb`,
`gbps`/`g`/`gb`, `tbps`/`t`/`tb`. Values are converted to bytes per second (bits ÷ 8).

### `trafficStats`

Exposes an HTTP API for per-user traffic statistics and online/offline state.

```yaml
trafficStats:
  listen: "127.0.0.1:8080"
  secret: "api-secret-token"    # required in X-Secret header
```

```toml
[trafficStats]
listen = "127.0.0.1:8080"
secret = "api-secret-token"
```

### `masquerade`

Hysteria 2 servers respond to plain HTTPS requests with masquerade content, making the server
appear as a regular web server to passive observers.

```yaml
# Return HTTP 404
masquerade:
  type: 404

# Return static string
masquerade:
  type: string
  string:
    content: "Hello, World!"
    statusCode: 200
    headers:
      Content-Type: "text/plain"

# Serve a local directory
masquerade:
  type: file
  file:
    dir: "/var/www/html"

# Reverse proxy to another server
masquerade:
  type: proxy
  proxy:
    url: "https://www.example.com"
    rewriteHost: true
```

```toml
# Return HTTP 404
[masquerade]
type = "404"
```

```toml
# Return static string
[masquerade]
type = "string"

[masquerade.string]
content = "Hello, World!"
statusCode = 200

[masquerade.string.headers]
Content-Type = "text/plain"
```

```toml
# Serve a local directory
[masquerade]
type = "file"

[masquerade.file]
dir = "/var/www/html"
```

```toml
# Reverse proxy to another server
[masquerade]
type = "proxy"

[masquerade.proxy]
url = "https://www.example.com"
rewriteHost = true
```

### `sniff`

Inspect proxied traffic to resolve the actual target domain/service, overriding the
connect address when applicable.

```yaml
sniff:
  enable: true
  timeout: "2s"
  rewriteDomain: false
  tcpPorts: "80,443,8080-8090"
  udpPorts: "all"
```

```toml
[sniff]
enable = true
timeout = "2s"
rewriteDomain = false
tcpPorts = "80,443,8080-8090"
udpPorts = "all"
```

### `resolver`

```yaml
# System resolver (default)
resolver:
  type: system

# DNS-over-HTTPS
resolver:
  type: https
  https:
    addr: "https://1.1.1.1/dns-query"
    timeout: "10s"
    sni: "cloudflare-dns.com"
    insecure: false
```

```toml
# System resolver (default)
[resolver]
type = "system"
```

```toml
# DNS-over-HTTPS
[resolver]
type = "https"

[resolver.https]
addr = "https://1.1.1.1/dns-query"
timeout = "10s"
sni = "cloudflare-dns.com"
insecure = false
```

### `acl` and `outbounds`

Route proxied connections to different upstreams based on address, domain, GeoIP, or GeoSite rules.

```yaml
outbounds:
  - name: direct
    type: direct
    direct:
      mode: auto        # auto | 46 | 64 | 4 | 6
                        # auto = dual-stack race
                        # 46 = prefer IPv4, 64 = prefer IPv6
                        # 4 = IPv4 only, 6 = IPv6 only
      bindIPv4: 192.0.2.10   # optional, cannot be combined with bindDevice
      bindIPv6: 2001:db8::10 # optional, cannot be combined with bindDevice
      bindDevice: eth0       # optional, Linux only, cannot be combined with bindIPv4/bindIPv6
      fastOpen: false        # Linux only
  - name: via-socks5
    type: socks5
    socks5:
      addr: "127.0.0.1:1080"
      username: user     # optional
      password: pass
  - name: via-http
    type: http
    http:
      url: "http://user:pass@proxy.example.com:8080"

acl:
  file: "/etc/hysteria/rules.yaml"
  geoip:  "/etc/hysteria/GeoLite2-Country.mmdb"
  geosite: "/etc/hysteria/geosite.dat"
```

```toml
[[outbounds]]
name = "direct"
type = "direct"

[outbounds.direct]
mode = "auto"      # auto | 46 | 64 | 4 | 6
bindIPv4 = "192.0.2.10"
bindIPv6 = "2001:db8::10"
# bindDevice = "eth0"
fastOpen = false

[[outbounds]]
name = "via-socks5"
type = "socks5"

[outbounds.socks5]
addr = "127.0.0.1:1080"
username = "user"
password = "pass"

[[outbounds]]
name = "via-http"
type = "http"

[outbounds.http]
url = "http://user:pass@proxy.example.com:8080"

[acl]
file = "/etc/hysteria/rules.yaml"
geoip = "/etc/hysteria/GeoLite2-Country.mmdb"
geosite = "/etc/hysteria/geosite.dat"
```

ACL rule format:

```yaml
# outbound  protocol  src_port  dst_port  matcher
- direct    tcp,udp   *         443       domain_suffix:.example.com
- reject    tcp       *         *         geoip:CN
- direct    tcp,udp   *         *         cidr:192.168.0.0/16
```

---

## Client Configuration

### Connection

```yaml
server: "your-server.example.com:443"
auth: "password"               # or "username:password"
```

```toml
server = "your-server.example.com:443"
auth = "password"  # or "username:password"
```

### `transport`

```yaml
# Standard UDP (default)
transport:
  type: udp

# UDP port-hopping: rotate source port every interval to defeat port-based blocking
transport:
  type: udp
  udp:
    hopInterval: "30s"
```

```toml
# Standard UDP (default)
[transport]
type = "udp"

# UDP port-hopping: rotate source port every interval to defeat port-based blocking
[transport]
type = "udp"

[transport.udp]
hopInterval = "30s"
```

The client `server` field supports port ranges for UDP hop, e.g. `"your-server.example.com:20000-34999"`.

### `tls`

```yaml
tls:
  sni: "server.example.com"
  insecure: false
  pinSHA256: "ba:78:16:bf:8f:01:cf:ea:41:41:40:de:5d:ae:22:23:b0:03:61:a3:96:17:7a:9c:b4:10:ff:61:f2:00:15:ad"
  ca: "/path/to/custom-ca.pem"
  clientCertificate: "/path/to/client.crt"   # mutual TLS
  clientKey: "/path/to/client.key"
```

```toml
[tls]
sni = "server.example.com"
insecure = false
pinSHA256 = "ba:78:16:bf:8f:01:cf:ea:41:41:40:de:5d:ae:22:23:b0:03:61:a3:96:17:7a:9c:b4:10:ff:61:f2:00:15:ad"
ca = "/path/to/custom-ca.pem"
clientCertificate = "/path/to/client.crt"
clientKey = "/path/to/client.key"
```

`pinSHA256` is the SHA-256 fingerprint of the server certificate (64 hex characters).
Colons, hyphens, and whitespace are stripped before parsing, so both
`ba:78:16:bf:...` and `ba7816bf...` are accepted.

### `obfs`

Same as server — must match server settings:

```yaml
obfs:
  type: salamander
  salamander:
    password: "obfuscation-password"
```

```toml
[obfs]
type = "salamander"

[obfs.salamander]
password = "obfuscation-password"
```

### `bandwidth`

Tell the server your available bandwidth. This activates Brutal (fixed-rate) congestion
control. To use BBR (auto-rate), omit the `bandwidth` section entirely.

```yaml
bandwidth:
  up:   "100 Mbps"
  down: "200 Mbps"
```

```toml
[bandwidth]
up = "100 Mbps"
down = "200 Mbps"
```

### `quic`

```yaml
quic:
  initStreamReceiveWindow:  8388608
  maxStreamReceiveWindow:   8388608
  initConnReceiveWindow:    20971520
  maxConnReceiveWindow:     20971520
  maxIdleTimeout:           "30s"
  keepAlivePeriod:          "20s"
```

```toml
[quic]
initStreamReceiveWindow = 8388608
maxStreamReceiveWindow = 8388608
initConnReceiveWindow = 20971520
maxConnReceiveWindow = 20971520
maxIdleTimeout = "30s"
keepAlivePeriod = "20s"
```

### `fastOpen`

```yaml
fastOpen: false   # true = return immediately without waiting for server TCP response (faster start)
lazy: false       # true = do not connect until a client actually connects
```

```toml
fastOpen = false  # true = return immediately without waiting for server TCP response (faster start)
lazy = false      # true = do not connect until a client actually connects
```

### Local proxy modes

Multiple local proxy modes can be active simultaneously:

```yaml
# SOCKS5 proxy
socks5:
  listen: "127.0.0.1:1080"
  username: "alice"  # optional
  password: "pass1"  # optional
  disableUDP: false

# HTTP/HTTPS proxy
http:
  listen: "127.0.0.1:8080"
  username: "alice"  # optional
  password: "pass1"  # optional
  realm: "rysteria"

# TCP port forwarding
tcpForwarding:
  - listen: "127.0.0.1:80"
    remote: "internal.example.com:80"

# UDP port forwarding
udpForwarding:
  - listen: "127.0.0.1:53"
    remote: "8.8.8.8:53"
    timeout: "20s"

# Transparent proxy (TPROXY, Linux only)
tcpTProxy:
  listen: "0.0.0.0:8080"
udpTProxy:
  listen: "0.0.0.0:8080"

# Transparent proxy (redirect, Linux only)
tcpRedirect:
  listen: "0.0.0.0:8080"

# TUN device (routes all traffic through the tunnel)
tun:
  name: "hy0"
  mtu: 1500
  timeout: "60s"
  address:
    ipv4: "198.18.0.1/15"
    ipv6: "fdfe:dcba:9876::1/18"
  route:
    strict: false
    ipv4: ["0.0.0.0/0"]
    ipv6: ["::/0"]
```

```toml
# SOCKS5 proxy
[socks5]
listen = "127.0.0.1:1080"
username = "alice"  # optional
password = "pass1"  # optional
disableUDP = false

# HTTP/HTTPS proxy
[http]
listen = "127.0.0.1:8080"
username = "alice"  # optional
password = "pass1"  # optional
realm = "rysteria"

# TCP port forwarding
[[tcpForwarding]]
listen = "127.0.0.1:80"
remote = "internal.example.com:80"

# UDP port forwarding
[[udpForwarding]]
listen = "127.0.0.1:53"
remote = "8.8.8.8:53"
timeout = "20s"

# Transparent proxy (TPROXY, Linux only)
[tcpTProxy]
listen = "0.0.0.0:8080"

[udpTProxy]
listen = "0.0.0.0:8080"

# Transparent proxy (redirect, Linux only)
[tcpRedirect]
listen = "0.0.0.0:8080"

# TUN device (routes all traffic through the tunnel)
[tun]
name = "hy0"
mtu = 1500
timeout = "60s"

[tun.address]
ipv4 = "198.18.0.1/15"
ipv6 = "fdfe:dcba:9876::1/18"

[tun.route]
strict = false
ipv4 = ["0.0.0.0/0"]
ipv6 = ["::/0"]
```

---

## YAML and TOML Syntax

Configuration files can be written as either YAML (`.yaml` / `.yml`) or TOML (`.toml`).
Both formats map to the same serde-backed schema and use the same field names,
including camelCase keys such as `fastOpen`, `speedTest`, and `ignoreClientBandwidth`.

### TOML notes

- Nested YAML objects become TOML tables:

```toml
[tls]
cert = "/path/to/cert.pem"
key = "/path/to/key.pem"
```

- YAML sequences of objects become TOML arrays of tables:

```toml
[[tcpForwarding]]
listen = "127.0.0.1:80"
remote = "internal.example.com:80"
```

- YAML maps become nested TOML tables:

```toml
[auth.userpass]
alice = "pass1"
bob = "pass2"
```

- Duration fields follow the same accepted formats as YAML examples:

```toml
maxIdleTimeout = "30s"
keepAlivePeriod = 20
```

### YAML syntax

Configuration files are parsed by [serde-saphyr](https://crates.io/crates/serde-saphyr)
with default options (`no_schema: false`). The behavior differs from strict YAML 1.2.

### Quoting rules

The parser does **not** enforce quoting by value type. Single quotes, double quotes, and
bare (unquoted) values are treated identically for all field types:

```yaml
# All three forms are equivalent for string fields:
listen: "0.0.0.0:443"
listen: '0.0.0.0:443'
listen: 0.0.0.0:443

# All three forms are equivalent for integer fields:
maxIncomingStreams: "1024"
maxIncomingStreams: '1024'
maxIncomingStreams: 1024
```

The only exception: bare `~` and `null` are always parsed as null/None. Use quotes
(`"null"`) if you need those as literal strings.

### Boolean fields

serde-saphyr accepts YAML 1.1 booleans (case-insensitive):

| True values | False values |
|-------------|--------------|
| `true`, `yes`, `y`, `on` | `false`, `no`, `n`, `off` |

All quote styles work:

```yaml
disableUDP: yes      # equivalent to true
speedTest: on        # equivalent to true
fastOpen: No         # equivalent to false
insecure: "false"    # equivalent to false
```

### Integer fields

Fields typed `u64`/`u32`/`u16` accept optional underscore separators and `0x` (hex),
`0o` (octal), `0b` (binary) prefixes. Spaces inside the numeric value are **not** allowed.

```yaml
initStreamReceiveWindow: 8_388_608   # OK: underscore separators
statusCode: 0x1F4                    # OK: hex (= 500)
maxIncomingStreams: 0                 # OK: zero
maxIncomingStreams: 1 024             # ERROR: space inside integer
```

### Duration fields

**Server duration fields** (e.g. `maxIdleTimeout`, `udpIdleTimeout`) are stored as strings
and parsed by an internal `parse_duration_like` function:

| Suffix | Unit |
|--------|------|
| `ms` | milliseconds |
| `s` | seconds |
| `m` | minutes |
| `h` | hours |
| *(none)* | seconds (bare integer defaults to seconds) |

A space between the number and unit is allowed. Quoting is optional.

```yaml
maxIdleTimeout: "30s"    # 30 seconds
maxIdleTimeout: 30s      # same, no quotes needed
maxIdleTimeout: "30 s"   # same, space OK
maxIdleTimeout: 30       # same, bare integer = seconds
udpIdleTimeout: "1 m"    # 1 minute
```

**Client duration fields** (e.g. `quic.maxIdleTimeout`, `quic.keepAlivePeriod`) use a
custom deserializer that accepts both integer and string forms. Integers are treated as
seconds; strings use the same unit suffixes.

```yaml
maxIdleTimeout: 30        # 30 seconds (integer form)
maxIdleTimeout: "30s"     # same (string form)
keepAlivePeriod: "20 s"   # 20 seconds, space OK
```

### Bandwidth fields

`bandwidth.up` and `bandwidth.down` use a dedicated parser with stricter rules:

- Format: `<integer><unit>`, case-insensitive, optional space between number and unit
- Units (decimal SI): `bps`/`b`, `kbps`/`k`/`kb`, `mbps`/`m`/`mb`, `gbps`/`g`/`gb`, `tbps`/`t`/`tb`
- Bare integers (no unit) are **invalid**
- Decimal numbers (e.g., `1.5 Gbps`) are **invalid**
- Values are converted to bytes per second (bits ÷ 8)

```yaml
bandwidth:
  up: 100 Mbps     # OK: 12.5 MB/s
  up: "1Gbps"      # OK: 125 MB/s
  up: 1G           # OK: shorthand
  up: 1000000      # ERROR: no unit
  up: 1.5 Gbps     # ERROR: decimal not supported
```

To use BBR congestion control (auto-rate), omit the `bandwidth` section or the individual
field. Setting `0` is not valid; the field must be absent to trigger BBR.

---

## CLI Reference

```
rysteria [OPTIONS] [COMMAND]

Options:
  -c, --config <FILE>         Config file path
  -l, --log-level <LEVEL>     Log level: debug|info|warn|error|none
                              [env: RYSTERIA_LOG_LEVEL]
  -f, --log-format <FORMAT>   Log format: console|json
                              [env: RYSTERIA_LOG_FORMAT]
  -h, --help                  Print help

Commands:
  server     Start the proxy server
  client     Start the proxy client (default when no command given)
  ping       TCP ping through the tunnel
  speedtest  Speed test through the tunnel
  version    Print version information
```

### `ping`

```bash
rysteria -c client.yaml ping example.com:80
```

Opens a TCP connection to the target through the proxy and reports round-trip time.

### `speedtest`

```bash
rysteria -c client.yaml speedtest [OPTIONS]

Options:
  --skip-download         Skip download test
  --skip-upload           Skip upload test
  --duration   <SECS>     Test duration in seconds (default: 10, time-based mode)
  --data-size  <BYTES>    Total data per direction (if set, switches to size-based mode)
  --use-bytes             Report speed in bytes/s instead of bits/s
```

When `--data-size` is given, the test transfers exactly that many bytes regardless of time.
When only `--duration` is given (default), the test runs for a fixed time window.

### `version`

```bash
rysteria version
```

Prints version number, build date, toolchain, git commit, platform, architecture, target
CPU, and library versions (quinn, h3, tokio).

---

## Protocol

Rysteria implements [Hysteria 2](https://v2.hysteria.network/docs/developers/Protocol/) at the
wire level.

### QUIC transport

- RFC 9000 QUIC for all traffic
- RFC 9221 QUIC datagrams for UDP relay
- Custom QUIC frame type `0x401` for TCP proxy streams
- HTTP/3 (RFC 9114) exclusively for the authentication handshake

### Authentication handshake

The client opens an HTTP/3 connection and sends:

```
POST /auth   (Host: hysteria/auth)
Hysteria-Auth:    <auth-credential>
Hysteria-CC-RX:   <client-rx-bandwidth-bps>
Hysteria-Padding: <256–2048 random alphanumeric bytes>
```

The server replies with HTTP status `233` on success:

```
233
Hysteria-UDP:     true|false
Hysteria-CC-RX:   <server-rx-bandwidth-bps>
Hysteria-Padding: <256–2048 random alphanumeric bytes>
```

### TCP stream

A new QUIC stream is opened per TCP connection:

```
Client → Server:
  [varint] frame type 0x401
  [varint] address length
  [bytes]  address ("host:port", max 2048 bytes)
  [varint] padding length
  [bytes]  padding (random, max 4096 bytes)
  <bidirectional data stream>

Server → Client:
  [u8]     status (0 = OK)
  [varint] message length
  [bytes]  message (on error, max 2048 bytes)
  [varint] padding length
  [bytes]  padding
  <bidirectional data stream>
```

### UDP relay

UDP packets are carried as QUIC datagrams (not H3 datagrams):

```
[u32]    session ID
[u16]    packet ID  (0 = unfragmented)
[u8]     fragment ID
[u8]     fragment count
[varint] address length
[bytes]  address ("host:port")
[varint] padding length
[bytes]  padding
[bytes]  UDP payload
```

Packets larger than 1200 bytes are split into multiple datagrams and reassembled by the peer.

### Congestion control

| Mode | Condition |
|------|-----------|
| **BBR** | Client reports `0` bandwidth, or server sets `ignoreClientBandwidth: true` |
| **Brutal** | Client reports a non-zero bandwidth; fixed-rate sending at that bitrate |

### Salamander obfuscation

Each UDP packet is XOR-encrypted with a keystream derived from BLAKE2b keyed with the
password. A random salt is prepended so every packet has a unique keystream. The result is
indistinguishable from uniform random bytes.

---

## Architecture

### Runtime model

Each QUIC connection is pinned to a single OS thread via `ShardPool`, a set of
`RyRuntime` instances that each run a current-thread Tokio runtime on a dedicated thread.
This eliminates cross-thread synchronization for the hot path.

| Runtime | Purpose |
|---------|---------|
| `ry-shard-{i}` | Per-connection QUIC pipeline (server) |
| `rysteria-quic-accept` | QUIC accept loop (server) |
| `rysteria-entry-svc` | Local proxy services: SOCKS5, HTTP, TProxy, TUN (client) |
| `rysteria-tunnel-keepalive` | Keepalive and reconnection (client) |
| `rysteria-traffic-stats` | Traffic statistics HTTP server (server, optional) |
| `rysteria-masq-tcp` | Masquerade HTTP server (server, optional) |

### Connection pipeline

```
┌────────────────────────── QUIC connection ──────────────────────────┐
│                                                                     │
│  ConnectionActor (server) / ClientConnActor (client)                │
│  ├── owns Scheduler directly (no Arc<Mutex>)                        │
│  ├── control_rx (bounded mpsc) ← AcquirePermit, FlowClosed, ...    │
│  ├── completion_rx (unbounded) ← SendDone from PermitReturnGuard   │
│  └── 3 pending queues: Control → Interactive → Bulk                 │
│                                                                     │
│  TcpFlowActor × N (pipelined double-buffer)                          │
│  ├── writes directly to its own QUIC SendStream (no serialization)  │
│  ├── acquires permit via AcquirePermit → oneshot response           │
│  ├── returns permit via PermitReturnGuard (RAII, unbounded channel) │
│  └── 2 permits in-flight: write(current) || acquire+read(next)     │
│                                                                     │
│  UDP relay                                                          │
│  └── sends UdpDatagram to actor; permit acquired atomically         │
└─────────────────────────────────────────────────────────────────────┘
```

TCP streams write directly to their own QUIC SendStream. Each stream has independent
QUIC flow control, so a slow receiver on one stream cannot block writes to other streams.

### Traffic scheduler

The `Scheduler` classifies flows by network-observable behavior (byte count, lifetime,
destination port) and enforces three-level backpressure through `PermitBank`.

**Three-level backpressure:**

Each permit is checked against three concurrent caps on the same in-flight bytes:

```
Connection cap: 32 MiB (all classes combined)
  ├── Control cap:           1 MiB (all Control flows combined)
  ├── Bulk cap:             30 MiB (all Bulk flows combined)
  └── RealtimeDatagram cap: 512 KiB (all UDP flows combined)
      └── Per-flow cap: 1 MiB (single flow max)
```

A permit requires all three levels to have sufficient credit. The same bytes are
deducted from the connection, class, and per-flow budgets simultaneously. Unused
credit is returned atomically when the send completes.

**Three flow classes** (highest priority first):

| Class | Budget | Heuristic |
|-------|--------|-----------|
| RealtimeDatagram | 512 KiB | UDP relay (games, VoIP, DNS) |
| Control | 1 MiB | Port 53/22/23/3389 (DNS, SSH, Telnet, RDP) |
| Bulk | 30 MiB | All TCP streams (default) |

Classification uses only network-layer observables. HTTPS content through SOCKS5/HTTP
CONNECT is encrypted end-to-end, making application-level inspection impossible.

**Early-interactive window:**

New TCP flows temporarily route to the Interactive pending queue (higher priority than
Bulk) for the first 128 KiB or 1500 ms. This ensures the first segments of new
connections (thumbnails, API calls, video initial segments) are served before pending
bulk transfers. Budget class is not overridden; flows draw from their actual class
budget at full speed.

**Priority-ordered pending queues:**

When budget is unavailable, permit requests queue in three priority-ordered queues.
Flush order: Control → Interactive → Bulk. This ensures small/new flows are not
starved by large bulk transfers under connection budget pressure.

**Pipelined upload (double-buffer):**

Each TCP flow uses two buffers and two permits to overlap the QUIC write of the
current chunk with the permit acquisition and TCP read of the next chunk:

```
write(chunk A) || acquire_permit(B) + read_tcp(B)
write(chunk B) || acquire_permit(C) + read_tcp(C)
...
```

This hides the permit channel round-trip (~50-100 us) behind the QUIC write,
roughly doubling single-flow upload throughput compared to stop-and-wait. Budget
impact is minimal: 2 x 32 KiB = 64 KiB per flow, or 0.2% of the 30 MiB Bulk cap.

### Graceful shutdown

Both server and client support two-phase Ctrl+C:

1. **First Ctrl+C**: graceful drain. New connections/streams are rejected; in-flight
   work is given 2 seconds to complete.
2. **Second Ctrl+C**: immediate `process::exit(1)`.

The server uses per-connection `TaskTracker` to track all in-flight work. The client
uses a two-layer drain: entry `TaskTracker` (handler tasks) and `TunnelWorkRegistry`
(proxy connections, auth, reconnect handles).

---

## Security Notes

- **Post-quantum TLS**: X25519MLKEM768 hybrid key exchange is the first offered group, providing
  forward secrecy against quantum adversaries for connections that negotiate it.
- **Certificate validation**: By default `sniGuard: dns-san` is enforced; disable only if you
  control both endpoints.
- **Obfuscation is not encryption**: Salamander hides the QUIC fingerprint and makes traffic
  look random; it does not replace the TLS encryption layer.
- **Padding**: All handshake messages include 256–4096 bytes of random padding to resist
  traffic-analysis attacks based on message size.

---

## Logging

### Levels

`debug` · `info` · `warn` · `error` · `none`

Set via `-l`/`--log-level` flag or `RYSTERIA_LOG_LEVEL` environment variable.

### Formats

**console** (default, colored):
```
2026-03-01T12:34:56Z  INFO  client connected  {"addr":"1.2.3.4:5678","id":"alice","tx":104857600}
```

**json** (one JSON object per line, suitable for log aggregators):
```json
{"time":1741000496000,"level":"info","msg":"client connected","addr":"1.2.3.4:5678","id":"alice","tx":104857600}
```

Set via `-f`/`--log-format` flag or `RYSTERIA_LOG_FORMAT` environment variable.

---

## Building for Release

The `hyperbole.py` script handles cross-compilation. Platform selection is controlled by
the `RY_APP_PLATFORMS` environment variable (comma-separated `os/arch` pairs). When not
set, it defaults to the native host target.

```bash
# Build for native host
python3 hyperbole.py build

# Build specific platforms
RY_APP_PLATFORMS="linux/amd64-musl,windows/amd64-avx,darwin/arm64" python3 hyperbole.py build

# Build all platforms from platforms.txt
RY_APP_PLATFORMS=all python3 hyperbole.py build

# Build debug binary (skips path-stripping and other release steps)
python3 hyperbole.py build --dev

# Run tests
python3 hyperbole.py test

# Format code
python3 hyperbole.py format

# Remove build/ and cargo cache
python3 hyperbole.py clean

# Show host info and supported platform list
python3 hyperbole.py about
```

Outputs land in `build/`. File naming convention:

```
rysteria-{os}-{arch}[.exe]

Examples:
  rysteria-linux-amd64
  rysteria-linux-amd64-avx
  rysteria-windows-arm64.exe
  rysteria-darwin-arm64
```

Build-time information embedded in every binary (visible via `rysteria version`):
- Git commit hash
- RFC3339 build timestamp (respects `SOURCE_DATE_EPOCH` for reproducible builds)
- Rust toolchain version
- Platform, architecture, target CPU
- Library versions (quinn, h3, tokio)

---

## Testing

```bash
# Unit tests (155 tests)
cargo test --lib

# Integration tests — client-server handshake, TCP proxy echo, UDP relay (12 tests)
cargo test --test integration

# Regression tests — historical failure modes, fault injection, port-hop recovery (15 tests)
cargo test --test regression

# Post-quantum key exchange negotiation (2 tests)
cargo test --test post_quantum

# Run all tests
cargo test
```

Regression tests include fault-injection scenarios via `FaultInjectionSocket`:
- **R14**: port-hop recovery under generation-aware packet drop
- **R15-A**: brief network interruption self-heals without tunnel rebuild
- **R15-B**: prolonged outage triggers TunnelManager reconnect

---

## License

See [LICENSE](LICENSE).

---

## Acknowledgements

- [Hysteria 2](https://v2.hysteria.network/) — original Go implementation and protocol specification
- [quinn](https://github.com/quinn-rs/quinn) — QUIC for Rust
- [rustls](https://github.com/rustls/rustls) — TLS for Rust
- [h3](https://github.com/hyperium/h3) — HTTP/3 for Rust
