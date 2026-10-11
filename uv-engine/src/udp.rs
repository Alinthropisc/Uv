use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use uv_core::error::UvResult;
use uv_core::traits::Scanner;
use uv_core::types::port::{Port, PortState};
use uv_core::types::protocol::Protocol;
use uv_core::types::result::ProbeResult;

pub struct UdpScanner {
    timeout: Duration,
}

impl UdpScanner {
    pub fn new(timeout_ms: u32) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms as u64),
        }
    }
}

/// Service-specific UDP probe payloads (mirrors masscan + nmap nse probes).
fn probe_payload(port: u16) -> &'static [u8] {
    match port {
        53  => b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
        123 => b"\xe3\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        161 => b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x71\xb4\xb5\x0f\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
        500 => b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        5353 => b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05local\x00\x00\x01\x00\x01",
        1900 => b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n",
        _   => b"\x00",  // generic empty probe
    }
}

#[async_trait]
impl Scanner for UdpScanner {
    async fn scan(&self, target: IpAddr, ports: &[Port]) -> UvResult<Vec<ProbeResult>> {
        let bind = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let mut results = Vec::with_capacity(ports.len());

        for &port in ports {
            let sock = UdpSocket::bind(bind).await?;
            let dst = SocketAddr::new(target, port.get());
            let payload = probe_payload(port.get());
            let _ = sock.send_to(payload, dst).await;
            let t0 = Instant::now();
            let mut buf = [0u8; 512];
            let probe = match timeout(self.timeout, sock.recv_from(&mut buf)).await {
                Ok(Ok(_)) => ProbeResult::open(port, Protocol::Udp, t0.elapsed()),
                Ok(Err(e)) if is_port_unreachable(&e) => ProbeResult::closed(port, Protocol::Udp),
                _ => {
                    let mut p = ProbeResult::filtered(port, Protocol::Udp);
                    p.state = PortState::OpenFiltered;
                    p
                }
            };
            results.push(probe);
        }
        Ok(results)
    }

    fn protocol(&self) -> Protocol {
        Protocol::Udp
    }
}

fn is_port_unreachable(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::ConnectionRefused
}
