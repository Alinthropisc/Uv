// Integration tests for uv scanners — mock-server style.
// Each test spins up a real TCP/UDP listener on localhost and verifies
// the scanner can detect the open port and grab the banner.
//
// NEVER runs cargo build/test on weak hardware without user request.
// These tests are written-only; run manually when hardware allows.

use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::thread;
use std::time::Duration;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Bind an ephemeral TCP port and return the port number + a thread that accepts one connection.
fn mock_tcp_server(banner: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        use std::io::Write;
        listener.set_nonblocking(false).ok();
        for _ in 0..32 {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.write_all(banner);
                }
                Err(_) => break,
            }
        }
    });
    port
}

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

// ─── TCP connect scanner ──────────────────────────────────────────────────────

#[tokio::test]
async fn tcp_connect_detects_open_port() {
    use uv_core::traits::Scanner;
    use uv_core::types::port::{Port, PortState};
    use uv_engine::tcp::TcpConnectScanner;

    let port = mock_tcp_server(b"SSH-2.0-OpenSSH_8.9\r\n");

    let scanner = TcpConnectScanner::new(2000);
    let ports = vec![Port(port)];
    let result = scanner.scan(LOCAL, &ports).await.unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].state, PortState::Open);
    assert_eq!(result[0].port.0, port);
}

#[tokio::test]
async fn tcp_connect_closed_port_is_closed() {
    use uv_core::traits::Scanner;
    use uv_core::types::port::{Port, PortState};
    use uv_engine::tcp::TcpConnectScanner;

    // Port 1 is almost certainly closed on any system
    let scanner = TcpConnectScanner::new(500);
    let ports = vec![Port(1)];
    let result = scanner.scan(LOCAL, &ports).await.unwrap();

    assert_eq!(result.len(), 1);
    assert_ne!(result[0].state, PortState::Open);
}

// ─── Banner grabber ───────────────────────────────────────────────────────────

#[tokio::test]
async fn banner_grabber_reads_ssh_banner() {
    use uv_core::traits::BannerGrabber;
    use uv_engine::banner::TcpBannerGrabber;

    let port = mock_tcp_server(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n");

    use uv_core::types::port::Port;
    use uv_core::types::protocol::Protocol;

    let grabber = TcpBannerGrabber::new(2000, 256);
    let info = grabber
        .grab(LOCAL, Port::new(port), Protocol::Tcp)
        .await
        .unwrap();

    let text = info
        .as_ref()
        .and_then(|s| s.banner.as_ref().and_then(|b| b.text.as_deref()))
        .unwrap_or("");
    assert!(
        text.contains("SSH-2.0"),
        "expected SSH banner, got: {text:?}"
    );
}

// ─── Version probe ────────────────────────────────────────────────────────────

#[tokio::test]
async fn version_probe_detects_ssh() {
    use uv_proto::version::default_probe_set;

    let port = mock_tcp_server(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n");

    let probes = default_probe_set(2000);
    let info = probes.detect(LOCAL, port).await;

    assert!(info.is_some(), "expected version info for SSH");
    let info = info.unwrap();
    assert_eq!(info.service, "ssh");
    assert!(
        info.version.contains("8.9"),
        "unexpected version: {}",
        info.version
    );
}

#[tokio::test]
async fn version_probe_detects_ftp() {
    use uv_proto::version::default_probe_set;

    let port = mock_tcp_server(b"220 ProFTPD 1.3.6 Server\r\n");
    let probes = default_probe_set(2000);
    let info = probes.detect(LOCAL, port).await;

    assert!(info.is_some());
    let info = info.unwrap();
    assert_eq!(info.service, "ftp");
}

// ─── SMACK banner matcher ─────────────────────────────────────────────────────

#[test]
fn smack_detects_ssh_banner() {
    use uv_proto::smack::{default_banner_smack, ServiceLabel};

    let smack = default_banner_smack();
    let banner = b"SSH-2.0-OpenSSH_8.9p1";
    let first = smack.first_match(banner);
    assert_eq!(first, Some(ServiceLabel::Ssh as usize));
}

#[test]
fn smack_detects_http_banner() {
    use uv_proto::smack::default_banner_smack;

    let smack = default_banner_smack();
    let banner = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24";
    assert!(smack.matches_any(banner));
}

#[test]
fn smack_no_false_positive_on_random() {
    use uv_proto::smack::default_banner_smack;

    let smack = default_banner_smack();
    let random = b"\x00\x01\x02\x03\x04\x05random binary data without service markers";
    assert!(!smack.matches_any(random));
}

// ─── Dedup ────────────────────────────────────────────────────────────────────

#[test]
fn dedup_removes_duplicate_ports() {
    use std::net::Ipv4Addr;
    use uv_core::types::port::Port;
    use uv_core::types::protocol::Protocol;
    use uv_core::types::result::{HostResult, ProbeResult, ScanResult};
    use uv_scan::dedup::dedup;

    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let mut host = HostResult::new(ip);
    host.ports.push(ProbeResult::open(
        Port(80),
        Protocol::Tcp,
        Duration::from_millis(10),
    ));
    host.ports.push(ProbeResult::open(
        Port(80),
        Protocol::Tcp,
        Duration::from_millis(10),
    ));
    host.ports.push(ProbeResult::open(
        Port(443),
        Protocol::Tcp,
        Duration::from_millis(10),
    ));

    let mut result = ScanResult {
        hosts: vec![host],
        duration_ms: 0,
        total_probes: 3,
        packets_sent: 0,
        packets_recv: 0,
    };
    dedup(&mut result);

    assert_eq!(
        result.hosts[0].ports.len(),
        2,
        "duplicate port 80 should be removed"
    );
}

// ─── BlackRock shuffle ────────────────────────────────────────────────────────

#[test]
fn blackrock_shuffle_is_permutation() {
    use uv_crypto::blackrock::{BlackRock, Permutation};

    let br = BlackRock::new(0xdeadbeef_cafebabe, 256);
    let mut seen = vec![false; 256];
    for i in 0..256u64 {
        let j = br.shuffle(i) as usize;
        assert!(!seen[j], "collision at index {i} → {j}");
        seen[j] = true;
    }
    assert!(seen.iter().all(|&s| s));
}

// ─── JA3 fingerprint ─────────────────────────────────────────────────────────

#[test]
fn ja3_known_hash() {
    use uv_crypto::ja3::Ja3Fields;

    // Known JA3 test vector: TLSv1.2, common ciphers
    let f = Ja3Fields {
        tls_version: 771, // 0x0303 = TLS 1.2
        ciphers: vec![
            49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161, 49171, 49172, 51, 57, 47, 53,
            10,
        ],
        extensions: vec![0, 23, 65281, 10, 11, 35, 16, 5, 13, 28],
        elliptic_curves: vec![29, 23, 24, 25],
        ec_point_formats: vec![0],
    };
    let hash = f.ja3();
    assert_eq!(hash.len(), 32); // MD5 is always 32 hex chars
}

// ─── UDP payloads ─────────────────────────────────────────────────────────────

#[test]
fn udp_payload_dns_defined() {
    use uv_proto::udp_payloads::udp_payload;
    assert!(udp_payload(53).is_some());
    assert!(udp_payload(123).is_some()); // NTP
    assert!(udp_payload(9999).is_none());
}

// ─── Binary encode/decode roundtrip ──────────────────────────────────────────

#[test]
fn binary_roundtrip_ipv4() {
    use std::net::Ipv4Addr;
    use uv_core::types::port::Port;
    use uv_core::types::protocol::Protocol;
    use uv_core::types::result::{HostResult, ProbeResult, ScanResult};
    use uv_output::binary::{decode_binary, encode_binary, BinaryRecord};

    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut host = HostResult::new(ip);
    host.ports.push(ProbeResult::open(
        Port(22),
        Protocol::Tcp,
        Duration::from_millis(5),
    ));

    let result = ScanResult {
        hosts: vec![host],
        duration_ms: 100,
        total_probes: 1,
        packets_sent: 0,
        packets_recv: 0,
    };
    let bytes = encode_binary(&result);
    let records = decode_binary(&bytes).unwrap();

    assert_eq!(records.len(), 1);
    if let BinaryRecord::V4 {
        ip: rip,
        port,
        proto,
        ..
    } = records[0]
    {
        assert_eq!(rip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(port, 22);
        assert_eq!(proto, 6); // TCP
    } else {
        panic!("expected V4 record");
    }
}
