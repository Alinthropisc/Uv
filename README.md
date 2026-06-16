# uv

Ultra-fast async port scanner. **masscan speed x nmap intelligence.** Rust async/await + C23 hybrid engine.

```
 ██╗   ██╗██╗   ██╗
 ██║   ██║██║   ██║
 ██║   ██║██║   ██║
 ██║   ██║╚██╗ ██╔╝
 ╚██████╔╝ ╚████╔╝
  ╚═════╝   ╚═══╝
```

---

## What is uv?

**uv** is a next-generation network scanner that combines masscan's raw-packet transmission speed with nmap's service detection intelligence. It is written in Rust (async/await) with a C23 engine for raw-socket operations, and is structured as a Cargo workspace of 11 focused crates.

Key design principles: SOLID, Strategy, Chain of Responsibility, Builder, Factory Method, Reactor, Newtype.

---

## Features

- SYN stealth scan via raw `AF_PACKET` sockets (requires root)
- BlackRock2 Feistel shuffle for randomized IP/port iteration
- SipHash, LCG, and SYN cookie implementation from masscan
- DPDK-style ring buffer and timing wheel for high-throughput packet dispatch
- Adaptive AIMD throttle to avoid saturating the network
- SMACK Aho-Corasick multi-pattern banner matching
- UDP probes for 18 well-known ports
- Binary format v2 supporting both IPv4 and IPv6, with resume and merge support
- Deduplication and live status reporter
- Active OS fingerprinting (FPEngine-style, from nmap)
- 22 NSE-style vulnerability checks
- 23 version/service probe sequences
- Timing templates T0 through T5
- Idle scan (`-sI`) and IP protocol scan (`-sO`)
- MAC OUI lookup and ARP sweep
- Port state reasons, RST filter, and traceroute
- JA3 / JA3S TLS fingerprinting
- Concurrent reverse DNS resolution
- 9 output formats (see table below)

---

## Architecture

### Workspace crates

| Crate | Role |
|-------|------|
| `uv` | CLI entry point, argument parsing, configuration |
| `uv-core` | Core types, traits, error handling, and shared abstractions |
| `uv-engine` | Async scan engine: task scheduling, Reactor loop, port dispatch |
| `uv-macros` | Procedural macros used across the workspace |
| `uv-crypto` | BlackRock2 Feistel shuffle, SipHash, LCG, SYN cookies |
| `uv-proto` | Service probes, banner grabbing, version detection (23 probes) |
| `uv-ffi` | C23 FFI bindings: raw AF_PACKET TX/RX ring, UDP ring |
| `uv-output` | Output formatters for all supported formats |
| `uv-scan` | Scan strategies: serial, random, manual; idle scan; IP proto scan |
| `uv-os` | OS fingerprinting (FPEngine-style), MAC OUI lookup, ARP, DNS |
| `uv-ports` | Port table, IP protocol table, SMACK Aho-Corasick matcher |
| `uv-vuln` | 22 vulnerability checks (Heartbleed, EternalBlue, Log4Shell, ...) |

### Technology layers

| Layer | Technology | Role |
|-------|-----------|------|
| Async runtime | Rust + async-std | Concurrent task scheduling, Reactor event loop |
| Raw transmit | C23 (`uv-ffi`) | AF_PACKET TX ring, 10 Mpps target |
| Intelligence | `uv-proto`, `uv-os` | Service detection, banner grab, OS fingerprint |
| CLI / logic | Rust (`uv`) | Argument parsing, output, config |

### Data flow

```
CLI args
  -> uv-engine (Reactor)
       -> uv-scan (port/IP order strategy)
            -> uv-ffi (C23 SYN sender / receiver)
                 -> open ports
                      -> uv-proto (service probe, banner)
                      -> uv-os (OS fingerprint, reverse DNS)
                      -> uv-vuln (vulnerability checks)
                           -> uv-output (format and write)
```

---

## Usage

```bash
# SYN stealth scan — requires root
sudo uv -a 192.168.1.1

# Scan a subnet, specific ports
sudo uv -a 192.168.1.0/24 -p 22,80,443,8080

# Full port range, fast timing (T4)
sudo uv -a 10.0.0.0/16 -p 1-65535 --timing T4

# Idle scan using a zombie host
sudo uv -a 192.168.1.1 -sI 192.168.1.254

# IP protocol scan
sudo uv -a 192.168.1.1 -sO

# Output as JSON
sudo uv -a 192.168.1.1 -o json -f results.json

# Greppable output
sudo uv -a 192.168.1.1 -oG results.gnmap

# Resume a previous scan
sudo uv --resume paused.scan

# Binary output (v2, supports IPv4 and IPv6)
sudo uv -a 2001:db8::/32 -o binary -f scan.bin

# Merge two binary scan files
uv --merge a.bin b.bin -f merged.bin

# Run vulnerability checks
sudo uv -a 192.168.1.1 --vuln

# Limit transmit rate (packets per second)
sudo uv -a 10.0.0.0/8 --rate 100000
```

Config file (`~/.config/.uv.toml`):

```toml
rate       = 50000
timeout_ms = 1500
timing     = "T3"
```

---

## Output formats

| Format | Flag | Description |
|--------|------|-------------|
| Plain (nmap-style) | `-o plain` | Human-readable table with port, state, service, version |
| Greppable | `-o greppable` / `-oG` | One line per host, nmap greppable style |
| JSON | `-o json` | Structured JSON array |
| XML | `-o xml` | nmap-compatible XML |
| NdJSON | `-o ndjson` | Newline-delimited JSON, one object per open port |
| Binary v2 | `-o binary` | Compact binary with IPv4/IPv6 support, resumable |
| Redis | `-o redis` | Writes results directly to a Redis instance |
| Certs (PEM) | `-o certs` | Extracts TLS certificates as PEM files |
| Unicornscan | `-o unicornscan` | Unicornscan-compatible output |

---

## Vulnerability checks

| Check | CVE / Reference |
|-------|----------------|
| Heartbleed | CVE-2014-0160 |
| EternalBlue | CVE-2017-0144 |
| Log4Shell | CVE-2021-44228 |
| Spring4Shell | CVE-2022-22965 |
| Shellshock | CVE-2014-6271 |
| ProxyLogon | CVE-2021-26855 |
| PrintNightmare | CVE-2021-1675 |
| ConfluenceRce | CVE-2022-26134 |
| GitLabRce | CVE-2021-22205 |
| RedisNoAuth | Unauthenticated Redis |
| MongoNoAuth | Unauthenticated MongoDB |
| ElasticsearchNoAuth | Unauthenticated Elasticsearch |
| DockerApi | Exposed Docker daemon API |
| KubernetesApi | Exposed Kubernetes API server |
| VncNoAuth | VNC with no authentication |
| MqttNoAuth | Unauthenticated MQTT broker |
| EtcdNoAuth | Unauthenticated etcd |
| MemcachedNoAuth | Unauthenticated Memcached |
| SmbSigning | SMB signing disabled |
| AnonFtp | Anonymous FTP login allowed |
| HttpOpenProxy | HTTP open proxy |
| DefaultCreds | Default credentials on common services |

---

## Requirements

- Linux (required for raw `AF_PACKET` sockets in SYN stealth mode)
- Root privileges for SYN stealth scan and raw-socket operations
- Rust stable or nightly (edition 2021, workspace)
- GCC 13+ or Clang 16+ with C23 support (for the C23 FFI layer compiled via `build.rs`)

```bash
cargo build --release
```

`build.rs` compiles the C23 sources via the `cc` crate and links them statically into the binary.

---

## Reference sources

The following upstream projects are included as read-only reference material under `masscan-master/`, `nmap-master/`, `ncrack-master/`, and `npcap-master/`. uv's own implementation is in the workspace crates listed above.

| Directory | Origin | License |
|-----------|--------|---------|
| `masscan-master/` | Robert Graham | MIT |
| `nmap-master/` | Gordon Lyon | NPSL |
| `ncrack-master/` | Nmap Project | GPL-2.0 |
| `npcap-master/` | Npcap authors | Npcap License |

---

## License

GPL-3.0-only
