use std::net::{IpAddr, SocketAddr, TcpListener};
use uv_core::traits::Scanner;
use uv_core::types::port::{Port, PortState};
use uv_core::types::protocol::Protocol;
use uv_engine::tcp::TcpConnectScanner;

fn bind_random_port() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

#[tokio::test]
async fn tcp_scanner_detects_open_port() {
    let (_listener, port) = bind_random_port();
    let scanner = TcpConnectScanner::new(500);
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let results = scanner.scan(target, &[Port(port)]).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].state, PortState::Open);
}

#[tokio::test]
async fn tcp_scanner_closed_port_not_open() {
    // Port 1 is almost always closed on localhost
    let scanner = TcpConnectScanner::new(300);
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let results = scanner.scan(target, &[Port(1)]).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_ne!(results[0].state, PortState::Open);
}

#[tokio::test]
async fn tcp_scanner_protocol_is_tcp() {
    let scanner = TcpConnectScanner::new(200);
    assert_eq!(scanner.protocol(), Protocol::Tcp);
}

#[tokio::test]
async fn tcp_scanner_multiple_ports() {
    let (_l1, p1) = bind_random_port();
    let (_l2, p2) = bind_random_port();
    let scanner = TcpConnectScanner::new(500);
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let results = scanner
        .scan(target, &[Port(p1), Port(p2), Port(1)])
        .await
        .unwrap();
    assert_eq!(results.len(), 3);
    let open: Vec<_> = results
        .iter()
        .filter(|r| r.state == PortState::Open)
        .collect();
    assert_eq!(open.len(), 2);
}
