// Scan pipeline — Chain of Responsibility + Strategy pattern.
// Stages: Discover → Enrich (banner/version) → OS detect → Vuln scan → Emit.
// Integrates: TimingTemplate, IpExcludeList, PortExcludeList, ResumeState, ScanType,
//             VulnEngine (uv-vuln), OsMatcher (uv-os), SctpScanner (uv-engine).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use futures::stream::{FuturesUnordered, StreamExt};
use tracing::{debug, info, instrument, warn};
use uv_core::scan_type::ScanType;
use uv_core::traits::{BannerGrabber, Scanner};
use uv_core::types::port::{Port, PortState};
use uv_core::types::result::{HostResult, ScanResult};
use uv_engine::banner::TcpBannerGrabber;
use uv_engine::rate::TokenBucketLimiter;
use uv_engine::sctp::SctpScanner;
use uv_engine::syn::SynStealthScanner;
use uv_engine::tcp::TcpConnectScanner;
use uv_engine::udp::UdpScanner;
use uv_os::{ActiveOsProber, OsDb, OsMatcher};
use uv_proto::version::default_probe_set;
use uv_vuln::VulnEngine;

use crate::job::ScanJob;
use crate::resume::ResumeState;
use crate::status::ScanStatus;
use crate::tracer;

#[instrument(skip(job), fields(
    targets  = job.targets.len(),
    scan_type = ?job.scan_type,
    timing   = ?job.timing,
))]
pub async fn run(job: &ScanJob) -> ScanResult {
    let start = Instant::now();

    // --- Timing template overrides ---
    let timing = job.timing.params();
    let rate_pps = if job.rate_pps > 0 {
        job.rate_pps
    } else {
        timing.rate_pps
    };
    let timeout_ms = if job.timeout_ms > 0 {
        job.timeout_ms
    } else {
        timing.timeout_ms
    };
    let concurrency = if job.concurrency > 0 {
        job.concurrency
    } else {
        timing.concurrency
    };
    let max_retries = if job.retries > 0 {
        job.retries
    } else {
        timing.max_retries
    };

    // --- Build port list, apply exclude list ---
    let mut ports: Vec<Port> = job.ports.iter().flat_map(|r| r.iter()).collect();
    if !job.port_exclude.is_empty() {
        ports.retain(|&p| !job.port_exclude.contains(p.0));
    }

    // BlackRock2 shuffle — avoids consecutive probes to same subnet
    if rate_pps > 0 && ports.len() > 1 {
        use uv_crypto::blackrock::{BlackRock, Permutation, ShuffleIter};
        let br = BlackRock::new(0xdeadbeef_cafebabe, ports.len() as u64);
        let perm: &dyn Permutation = &br;
        ports = ShuffleIter::new(perm).map(|i| ports[i as usize]).collect();
    }
    let ports = Arc::new(ports);

    // --- Filter targets by IP exclude list ---
    let mut targets: Vec<IpAddr> = job
        .targets
        .iter()
        .copied()
        .filter(|ip| {
            if job.ip_exclude.contains(*ip) {
                tracer::log_excluded(*ip, "ip-exclude-list");
                false
            } else {
                true
            }
        })
        .collect();

    // --- masscan shard filter: keep targets[shard-1 :: shards] ---
    if job.shards > 1 {
        let idx = (job.shard.saturating_sub(1)) as usize;
        targets = targets
            .into_iter()
            .enumerate()
            .filter(|(i, _)| i % job.shards as usize == idx)
            .map(|(_, ip)| ip)
            .collect();
        debug!(
            shard = job.shard,
            shards = job.shards,
            kept = targets.len(),
            "shard filter applied"
        );
    }

    tracer::log_job_start(targets.len(), ports.len(), rate_pps, job.timing.label());

    // --- Live progress reporter (masscan --status style) ---
    let total_work = targets.len() as u64 * ports.len() as u64;
    let (status_reporter, done_counter) = ScanStatus::new(total_work);
    let _status_handle = status_reporter.spawn(1);

    // --- Resume state ---
    let resume: Option<Arc<tokio::sync::Mutex<ResumeState>>> =
        job.resume_file.as_ref().map(|path| {
            Arc::new(tokio::sync::Mutex::new(
                ResumeState::load(path).unwrap_or_default(),
            ))
        });

    // --- Rate limiter ---
    let limiter: Option<Arc<TokenBucketLimiter>> = if rate_pps > 0 {
        Some(Arc::new(TokenBucketLimiter::with_rate(rate_pps)))
    } else {
        None
    };

    // --- Shared resources ---
    let grabber = Arc::new(TcpBannerGrabber::new(timeout_ms, 4096));
    let probe_set = Arc::new(default_probe_set(timeout_ms));
    let vuln_eng = if job.vuln_scan {
        Some(Arc::new(VulnEngine::default_engine()))
    } else {
        None
    };
    let os_matcher = if job.os_detect {
        Some(Arc::new(OsMatcher::new(OsDb::built_in())))
    } else {
        None
    };

    let scan_type = job.scan_type;
    let no_banner = job.no_banner;
    let open_only = job.open_only;

    // --- Stage 1: Discover all hosts concurrently ---
    let mut host_tasks: FuturesUnordered<_> = FuturesUnordered::new();

    for ip in targets {
        let ports_ref = Arc::clone(&ports);
        let lim = limiter.clone();
        let grab_ref = Arc::clone(&grabber);
        let probe_ref = Arc::clone(&probe_set);
        let resume_ref = resume.clone();
        let vuln_ref = vuln_eng.clone();
        let os_ref = os_matcher.clone();
        let done_ref = Arc::clone(&done_counter);

        host_tasks.push(async move {
            // --- Dispatch scanner by ScanType ---
            let mut probes = match scan_type {
                ScanType::Udp => {
                    let scanner = UdpScanner::new(timeout_ms);
                    match scanner.scan(ip, &ports_ref).await {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(%ip, err = %e, "UDP scan error");
                            return HostResult::new(ip);
                        }
                    }
                }
                ScanType::SctpInit => {
                    let scanner = SctpScanner::init(timeout_ms);
                    match scanner.scan(ip, &ports_ref).await {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(%ip, err = %e, "SCTP INIT scan error");
                            return HostResult::new(ip);
                        }
                    }
                }
                ScanType::SctpCookieEcho => {
                    let scanner = SctpScanner::cookie_echo(timeout_ms);
                    match scanner.scan(ip, &ports_ref).await {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(%ip, err = %e, "SCTP COOKIE-ECHO scan error");
                            return HostResult::new(ip);
                        }
                    }
                }
                ScanType::SynStealth => {
                    let scanner = SynStealthScanner::new(timeout_ms);
                    match scanner.scan(ip, &ports_ref).await {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(%ip, err = %e, "SYN stealth scan error — falling back to TcpConnect");
                            let fallback = TcpConnectScanner::new(timeout_ms).with_concurrency(concurrency);
                            match fallback.scan(ip, &ports_ref).await {
                                Ok(p) => p,
                                Err(_) => return HostResult::new(ip),
                            }
                        }
                    }
                }
                // Exotic flags (NULL/FIN/Xmas/ACK/Window) + default TcpConnect
                _ => {
                    let mut scanner =
                        TcpConnectScanner::new(timeout_ms).with_concurrency(concurrency);
                    if let Some(l) = lim {
                        scanner = scanner.with_limiter(l as Arc<dyn uv_core::traits::RateLimiter>);
                    }
                    match scanner.scan(ip, &ports_ref).await {
                        Ok(p) => p,
                        Err(_) => return HostResult::new(ip),
                    }
                }
            };

            // --- Mark resume progress ---
            if let Some(ref res) = resume_ref {
                let mut state = res.lock().await;
                for probe in &probes {
                    let _ = state.mark_done(ip, probe.port.0);
                }
            }

            // --- Retry filtered ports with exponential backoff ---
            if max_retries > 0 {
                let filtered: Vec<Port> = probes
                    .iter()
                    .filter(|p| p.state == PortState::Filtered)
                    .map(|p| p.port)
                    .collect();

                if !filtered.is_empty() {
                    for attempt in 1..=max_retries {
                        let delay_ms = (timing.min_rtt_ms as u64) * (1 << attempt.min(5));
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        tracer::log_retry(ip, 0, attempt);

                        let retry = TcpConnectScanner::new(timeout_ms)
                            .with_concurrency(concurrency.min(32));
                        if let Ok(results) = retry.scan(ip, &filtered).await {
                            for r in results {
                                if r.state == PortState::Open {
                                    if let Some(p) = probes.iter_mut().find(|p| p.port == r.port) {
                                        *p = r;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // --- Stage 2: Banner + version detection on open TCP ports ---
            if !no_banner {
                for probe in probes.iter_mut().filter(|p| p.state == PortState::Open) {
                    // 2a: version probe (nmap-probes style) — richer than raw banner
                    if let Some(ver) = probe_ref.detect(ip, probe.port.0).await {
                        tracer::log_open_port(ip, probe.port.0, Some(ver.service));
                        let kind =
                            uv_core::types::protocol::ServiceKind::Unknown(ver.service.to_string());
                        let mut svc = uv_core::types::banner::ServiceInfo::new(kind).with_version(
                            format!("{} {}", ver.product, ver.version)
                                .trim()
                                .to_string(),
                        );
                        if let Some(extra) = ver.extra {
                            svc.extra = Some(extra);
                        }
                        probe.service = Some(svc);
                    } else if let Ok(Some(svc)) = grab_ref.grab(ip, probe.port, probe.proto).await {
                        // 2b: fallback to raw banner
                        tracer::log_open_port(ip, probe.port.0, Some(&svc.service.to_string()));
                        probe.service = Some(svc);
                    } else {
                        tracer::log_open_port(ip, probe.port.0, None);
                    }
                }
            }

            // --- Stage 3: Vuln scan on open ports ---
            let mut host_vulns = Vec::new();
            if let Some(ref engine) = vuln_ref {
                for probe in probes.iter().filter(|p| p.state == PortState::Open) {
                    for r in engine.run(ip, probe.port.0).await {
                        if r.vulnerable {
                            tracer::log_vuln(
                                ip,
                                probe.port.0,
                                r.check,
                                r.severity.label(),
                                &r.detail,
                            );
                            host_vulns.push(uv_core::types::result::VulnEntry {
                                check: r.check.to_string(),
                                severity: r.severity.label().to_string(),
                                detail: r.detail.clone(),
                                cve: r.cve.map(str::to_string),
                            });
                        }
                    }
                }
            }

            // --- Stage 4: OS fingerprint (passive TTL + active TCP probes) ---
            let host_os: Vec<uv_core::types::result::OsEntry> = if let Some(ref matcher) = os_ref {
                let passive_ttl = probes.iter().find_map(|p| p.ttl);
                let fp = if let Some(open_port) = probes.iter().find(|p| p.state == PortState::Open)
                {
                    let prober = ActiveOsProber::new(timeout_ms);
                    prober.probe(ip, open_port.port.0, 1, passive_ttl).await
                } else {
                    build_fingerprint_from_probes(&probes)
                };
                let matches = matcher.match_fp(&fp);
                if let Some(best) = matches.first() {
                    info!(%ip, os = %best.name, accuracy = best.accuracy, "OS detected");
                }
                matches
                    .into_iter()
                    .map(|m| uv_core::types::result::OsEntry {
                        name: m.name,
                        accuracy: m.accuracy,
                        os_class: m.os_class,
                        cpe: m.cpe,
                    })
                    .collect()
            } else {
                vec![]
            };

            // --- Tick progress counter ---
            done_ref.fetch_add(probes.len() as u64, std::sync::atomic::Ordering::Relaxed);

            // --- Filter to open-only if requested ---
            if open_only {
                probes.retain(|p| p.state == PortState::Open);
            }

            let mut host = HostResult::new(ip);
            host.ports = probes;
            host.vulns = host_vulns;
            host.os_matches = host_os;
            host
        });
    }

    let mut hosts: Vec<HostResult> = Vec::new();
    let mut total_probes: u64 = 0;
    let mut total_open: u64 = 0;

    while let Some(host) = host_tasks.next().await {
        let open = host
            .ports
            .iter()
            .filter(|p| p.state == PortState::Open)
            .count();
        tracer::log_host_result(
            host.addr,
            open,
            host.ports.len(),
            start.elapsed().as_millis() as u64,
        );
        total_open += open as u64;
        total_probes += host.ports.len() as u64;
        hosts.push(host);
    }

    // --- Dedup (masscan main-dedup.c style) ---
    let mut scan_tmp = ScanResult {
        hosts,
        duration_ms: 0,
        total_probes,
        packets_sent: 0,
        packets_recv: 0,
    };
    crate::dedup::dedup(&mut scan_tmp);
    let mut hosts = scan_tmp.hosts;

    // --- DNS reverse lookup — concurrent via FuturesUnordered ---
    {
        let mut dns_tasks: FuturesUnordered<_> = hosts
            .iter()
            .enumerate()
            .filter(|(_, h)| h.hostname.is_none())
            .map(|(idx, h)| {
                let ip = h.addr;
                async move { (idx, reverse_dns(ip).await) }
            })
            .collect();
        while let Some((idx, name)) = dns_tasks.next().await {
            if let Some(n) = name {
                hosts[idx].hostname = Some(n);
            }
        }
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    let rate = if duration_ms > 0 {
        total_probes as f64 / (duration_ms as f64 / 1000.0)
    } else {
        0.0
    };
    tracer::log_scan_complete(hosts.len(), total_open, duration_ms, rate);

    ScanResult {
        hosts,
        duration_ms,
        total_probes,
        packets_sent: 0,
        packets_recv: 0,
    }
}

/// Build a minimal OsFingerprint from observed probe results (TTL, TCP options).
/// Reverse DNS lookup — returns PTR record for the IP if available.
async fn reverse_dns(ip: IpAddr) -> Option<String> {
    let sa = std::net::SocketAddr::new(ip, 0);
    tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        // Trick: format as socket addr then resolve — gets PTR via getaddrinfo
        let dummy = format!("{}:0", ip);
        dummy.to_socket_addrs().ok()?.next().and_then(|_| {
            // std doesn't expose PTR; use getnameinfo via libc fallback
            getnameinfo(sa)
        })
    })
    .await
    .ok()
    .flatten()
}

#[cfg(unix)]
fn getnameinfo(sa: std::net::SocketAddr) -> Option<String> {
    let mut host = [0i8; 256];
    let (addr_ptr, addr_len) = match sa {
        std::net::SocketAddr::V4(v4) => {
            let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            raw.sin_family = libc::AF_INET as libc::sa_family_t;
            raw.sin_port = 0;
            raw.sin_addr = libc::in_addr {
                s_addr: u32::from(*v4.ip()).to_be(),
            };
            let ptr = Box::into_raw(Box::new(raw)) as *const libc::sockaddr;
            (
                ptr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        std::net::SocketAddr::V6(v6) => {
            let octets = v6.ip().octets();
            let mut raw: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            raw.sin6_port = 0;
            raw.sin6_flowinfo = 0;
            raw.sin6_addr = libc::in6_addr { s6_addr: octets };
            raw.sin6_scope_id = 0;
            let ptr = Box::into_raw(Box::new(raw)) as *const libc::sockaddr;
            (
                ptr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    };
    let ret = unsafe {
        libc::getnameinfo(
            addr_ptr,
            addr_len,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    unsafe { drop(Box::from_raw(addr_ptr as *mut libc::sockaddr_in)) };
    if ret == 0 {
        let cstr = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) };
        cstr.to_str().ok().map(|s| s.to_owned())
    } else {
        None
    }
}

#[cfg(not(unix))]
fn getnameinfo(_sa: std::net::SocketAddr) -> Option<String> {
    None
}

fn build_fingerprint_from_probes(
    probes: &[uv_core::types::result::ProbeResult],
) -> uv_os::OsFingerprint {
    use uv_os::OsFingerprint;

    let mut fp = OsFingerprint::default();

    // Derive TTL from first probe that has one
    if let Some(ttl) = probes.iter().find_map(|p| p.ttl) {
        fp.ttl_guess = Some(OsFingerprint::guess_ttl(ttl));
    }

    fp
}
