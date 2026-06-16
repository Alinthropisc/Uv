use std::net::SocketAddr;
use std::sync::Arc;

use uv_core::traits::BannerGrabber;
use uv_core::types::port::Port;
use uv_core::types::port::PortState;
use uv_core::types::protocol::Protocol;
use uv_core::types::result::{HostResult, ProbeResult, ScanResult};
use uv_engine::banner::TcpBannerGrabber;

/// Enrich open sockets discovered by the port scanner with banner / service info.
/// Returns a `ScanResult` populated from the provided `open_sockets`.
pub async fn enrich(open_sockets: &[SocketAddr], timeout_ms: u32, no_banner: bool) -> ScanResult {
    use std::collections::HashMap;
    use std::time::Instant;

    let grabber: Arc<dyn BannerGrabber> = Arc::new(TcpBannerGrabber::new(timeout_ms, 512));

    let t0 = Instant::now();
    let mut hosts: HashMap<std::net::IpAddr, HostResult> = HashMap::new();
    let mut handles = Vec::new();

    for &sock in open_sockets {
        let g = Arc::clone(&grabber);
        handles.push(tokio::spawn(async move {
            let port = Port::new(sock.port());
            let svc = if no_banner {
                None
            } else {
                g.grab(sock.ip(), port, Protocol::Tcp).await.unwrap_or(None)
            };
            (sock, port, svc)
        }));
    }

    let total = handles.len() as u64;
    for h in handles {
        if let Ok((sock, port, svc)) = h.await {
            let mut probe =
                ProbeResult::open(port, Protocol::Tcp, std::time::Duration::from_millis(0));
            probe.state = PortState::Open;
            if let Some(s) = svc {
                probe = probe.with_service(s);
            }
            hosts
                .entry(sock.ip())
                .or_insert_with(|| HostResult::new(sock.ip()))
                .ports
                .push(probe);
        }
    }

    ScanResult {
        hosts: hosts.into_values().collect(),
        duration_ms: t0.elapsed().as_millis() as u64,
        total_probes: total,
        packets_sent: total,
        packets_recv: total,
    }
}

/// Pretty-print a `ScanResult` to stdout (non-greppable mode).
pub fn print_results(result: &ScanResult, greppable: bool) {
    for host in &result.hosts {
        let open: Vec<_> = host.open_ports().collect();
        if open.is_empty() {
            continue;
        }
        if greppable {
            let ports: Vec<String> = open.iter().map(|p| p.port.to_string()).collect();
            println!("{} -> [{}]", host.addr, ports.join(","));
        } else {
            println!("\n[+] {}", host.addr);
            for p in open {
                let svc = p
                    .service
                    .as_ref()
                    .map(|s| format!("  {}", s.service))
                    .unwrap_or_default();
                let banner = p
                    .service
                    .as_ref()
                    .and_then(|s| s.banner.as_ref())
                    .and_then(|b| b.text.as_deref())
                    .map(|t| format!("  \"{t}\""))
                    .unwrap_or_default();
                println!("    {}/tcp  open{svc}{banner}", p.port);
            }
        }
    }
    println!(
        "\n[*] {} open port(s) in {}ms",
        result.open_count(),
        result.duration_ms
    );
}
