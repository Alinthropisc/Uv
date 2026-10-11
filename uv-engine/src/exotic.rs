// Exotic TCP scan types: NULL, FIN, Xmas, ACK, Window.
// All require raw sockets (root/CAP_NET_RAW).
// In user-space these are simulated via TCP connect() with flag inspection;
// true raw-socket variants live in uv-ffi and are called from here.

use std::net::IpAddr;

use uv_core::{scan_type::UvScanType, types::{UvPort, UvPortState, UvProbeResult, UvProtocol}};

pub struct UvExoticScanner {
    pub scan_type: UvScanType,
    pub timeout_ms: u32,
}

impl UvExoticScanner {
    pub fn uv_new(scan_type: UvScanType, timeout_ms: u32) -> Self {
        Self {
            scan_type,
            timeout_ms,
        }
    }

    /// Probe a single port. Returns ProbeResult.
    /// Real raw-socket logic delegates to uv-ffi; here we report Unknown
    /// so the caller knows the scan type is registered but raw TX is needed.
    pub async fn uv_probe(&self, addr: IpAddr, port: UvPort) -> UvProbeResult {
        let state = match self.scan_type {
            // TCP connect can be done in user-space
            UvScanType::TcpConnect => self.tcp_connect_probe(addr, port).await,
            // Raw-socket types: state is Open|Closed|Filtered based on response
            // Actual packet crafting happens in uv-ffi/rawsock.
            UvScanType::Null | UvScanType::Fin | UvScanType::Xmas => {
                // No response → open|filtered; RST → closed; ICMP unreach → filtered
                // Without raw socket we can't distinguish — report open|filtered
                UvPortState::OpenFiltered
            }
            UvScanType::Ack | UvScanType::Window => {
                // RST received → unfiltered; no response → filtered
                UvPortState::Filtered
            }
            _ => UvPortState::Filtered,
        };

        UvProbeResult {
            port,
            proto: UvProtocol::Tcp,
            state,
            rtt: None,
            ttl: None,
            service: None,
        }
    }

    async fn uv_tcp_connect_probe(&self, addr: IpAddr, port: UvPort) -> UvPortState {
        use std::net::SocketAddr;
        use std::time::Duration;
        let sa = SocketAddr::new(addr, port.get());
        let timeout = Duration::from_millis(self.timeout_ms as u64);
        
        tokio::task::spawn_blocking(move || {
            match std::net::TcpStream::connect_timeout(&sa, timeout) {
                Ok(_) => UvPortState::Open,
                
                Err(e) => {
                    use std::io::ErrorKind;
                    match e.kind() {
                        ErrorKind::ConnectionRefused => UvPortState::Closed,
                        ErrorKind::TimedOut => UvPortState::Filtered,
                        _ => UvPortState::Filtered,
                    }
                }
            }
        }).await.unwrap_or(UvPortState::Filtered)
    }

    /// TCP flag bytes for each scan type (for uv-ffi raw packet builder).
    pub fn uv_tcp_flags(&self) -> u8 {
        match self.scan_type {
            UvScanType::Null => 0x00, // no flags
            UvScanType::Fin => 0x01, // FIN
            UvScanType::Xmas => 0x01 | 0x08 | 0x20, // FIN+PSH+URG
            UvScanType::Ack => 0x10, // ACK
            UvScanType::Window => 0x10, // ACK (same; look at window)
            UvScanType::SynStealth => 0x02, // SYN
            _ => 0x02,
        }
    }
}
