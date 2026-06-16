use std::net::IpAddr;
use std::time::Duration;
use uv_core::types::banner::{Banner, ServiceInfo};
use uv_core::types::ip::{CidrRange, IpTarget};
use uv_core::types::port::{Port, PortRange, PortState};
use uv_core::types::protocol::{Protocol, ServiceKind};
use uv_core::types::result::{HostResult, ProbeResult, ScanResult};

// --- IP types ---

#[test]
fn cidr_host_count_v4_24() {
    let cidr = CidrRange::parse("192.168.1.0/24").unwrap();
    assert_eq!(cidr.host_count(), 256);
}

#[test]
fn cidr_host_count_v4_32() {
    let cidr = CidrRange::parse("10.0.0.1/32").unwrap();
    assert_eq!(cidr.host_count(), 1);
}

#[test]
fn cidr_invalid_prefix_rejected() {
    assert!(CidrRange::parse("10.0.0.0/33").is_err());
}

#[test]
fn ip_target_single() {
    let t = IpTarget::parse("1.2.3.4").unwrap();
    assert!(matches!(t, IpTarget::Single(_)));
}

#[test]
fn ip_target_cidr() {
    let t = IpTarget::parse("10.0.0.0/8").unwrap();
    assert!(matches!(t, IpTarget::Cidr(_)));
}

#[test]
fn ip_target_hostname() {
    let t = IpTarget::parse("example.com").unwrap();
    assert!(matches!(t, IpTarget::Hostname(_)));
}

// --- Port types ---

#[test]
fn port_range_iter_count() {
    let r = PortRange::new(80, 89).unwrap();
    assert_eq!(r.iter().count(), 10);
}

#[test]
fn port_range_all_has_65535_ports() {
    assert_eq!(PortRange::all().count(), 65535);
}

#[test]
fn port_range_invalid_reversed() {
    assert!(PortRange::new(90, 80).is_err());
}

#[test]
fn port_parse_single() {
    let r = PortRange::parse("443").unwrap();
    assert_eq!(r.start, Port(443));
    assert_eq!(r.count(), 1);
}

#[test]
fn port_display() {
    assert_eq!(Port(80).to_string(), "80");
}

#[test]
fn port_state_display() {
    assert_eq!(PortState::Open.to_string(), "open");
    assert_eq!(PortState::OpenFiltered.to_string(), "open|filtered");
}

// --- Protocol / ServiceKind ---

#[test]
fn service_from_port_known() {
    assert!(matches!(
        ServiceKind::from_port(22, Protocol::Tcp),
        ServiceKind::Ssh
    ));
    assert!(matches!(
        ServiceKind::from_port(443, Protocol::Tcp),
        ServiceKind::Https
    ));
    assert!(matches!(
        ServiceKind::from_port(53, Protocol::Udp),
        ServiceKind::Dns
    ));
}

#[test]
fn service_from_port_unknown() {
    let s = ServiceKind::from_port(12345, Protocol::Tcp);
    assert!(matches!(s, ServiceKind::Unknown(_)));
}

// --- Banner ---

#[test]
fn banner_from_utf8_bytes() {
    let b = Banner::from_bytes(b"SSH-2.0-OpenSSH_8.9".to_vec(), false);
    assert_eq!(b.text.as_deref(), Some("SSH-2.0-OpenSSH_8.9"));
    assert!(!b.tls);
}

#[test]
fn banner_from_binary_has_no_text() {
    let b = Banner::from_bytes(vec![0xff, 0xfe, 0x00], false);
    assert!(b.text.is_none());
}

#[test]
fn service_info_builder() {
    let svc = ServiceInfo::new(ServiceKind::Ssh)
        .with_version("OpenSSH_8.9")
        .with_banner(Banner::from_bytes(b"SSH-2.0".to_vec(), false));
    assert_eq!(svc.version.as_deref(), Some("OpenSSH_8.9"));
    assert!(svc.banner.is_some());
}

// --- Results ---

#[test]
fn probe_result_open() {
    let p = ProbeResult::open(Port(80), Protocol::Tcp, Duration::from_millis(10));
    assert_eq!(p.state, PortState::Open);
    assert!(p.rtt.is_some());
}

#[test]
fn host_result_open_ports_filtered() {
    let mut h = HostResult::new("127.0.0.1".parse::<IpAddr>().unwrap());
    h.ports.push(ProbeResult::open(
        Port(80),
        Protocol::Tcp,
        Duration::from_millis(5),
    ));
    h.ports.push(ProbeResult::closed(Port(81), Protocol::Tcp));
    assert_eq!(h.open_ports().count(), 1);
}

#[test]
fn scan_result_open_count() {
    let mut r = ScanResult::new();
    let mut host = HostResult::new("10.0.0.1".parse::<IpAddr>().unwrap());
    host.ports.push(ProbeResult::open(
        Port(22),
        Protocol::Tcp,
        Duration::from_millis(1),
    ));
    host.ports.push(ProbeResult::open(
        Port(80),
        Protocol::Tcp,
        Duration::from_millis(2),
    ));
    host.ports
        .push(ProbeResult::closed(Port(443), Protocol::Tcp));
    r.hosts.push(host);
    assert_eq!(r.open_count(), 2);
}
