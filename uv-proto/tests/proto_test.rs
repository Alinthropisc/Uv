use uv_proto::banner::ParserChain;
use uv_proto::parsers::default_chain;

fn chain() -> ParserChain {
    default_chain()
}

#[test]
fn ssh_parsed() {
    let b = b"SSH-2.0-OpenSSH_9.3p1 Ubuntu-1";
    let r = chain().parse(b, 22);
    assert_eq!(r.service, "ssh");
    assert_eq!(r.version.as_deref(), Some("OpenSSH_9.3p1"));
}

#[test]
fn ssh_proto_in_info() {
    let r = chain().parse(b"SSH-2.0-dropbear_2022.83", 22);
    assert_eq!(r.service, "ssh");
    assert!(r.info.as_deref().unwrap_or("").contains("2.0"));
}

#[test]
fn http_200_parsed() {
    let b = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\n\r\n";
    let r = chain().parse(b, 80);
    assert_eq!(r.service, "http");
    assert!(r.version.as_deref().unwrap_or("").contains("nginx"));
    assert!(r.info.as_deref().unwrap_or("").contains("200"));
}

#[test]
fn https_443_service() {
    let b = b"HTTP/1.1 301 Moved\r\n\r\n";
    let r = chain().parse(b, 443);
    assert_eq!(r.service, "https");
}

#[test]
fn ftp_banner_parsed() {
    let r = chain().parse(b"220 ProFTPD 1.3.8 Server ready", 21);
    assert_eq!(r.service, "ftp");
    assert!(r.version.as_deref().unwrap_or("").contains("ProFTPD"));
}

#[test]
fn smtp_banner_parsed() {
    let r = chain().parse(b"220 mail.example.com ESMTP Postfix", 25);
    assert_eq!(r.service, "smtp");
}

#[test]
fn ssl_tls12_banner() {
    // TLS 1.2 ServerHello record header
    let b = &[0x16u8, 0x03, 0x03, 0x00, 0x40];
    let r = chain().parse(b, 8443);
    assert_eq!(r.service, "tls");
    assert_eq!(r.version.as_deref(), Some("TLS 1.2"));
}

#[test]
fn dns_response_parsed() {
    let mut pkt = [0u8; 12];
    pkt[2] = 0x81;
    pkt[3] = 0x80; // QR=1, NOERROR
    let r = chain().parse(&pkt, 53);
    assert_eq!(r.service, "dns");
    assert_eq!(r.info.as_deref(), Some("NOERROR"));
}

#[test]
fn unknown_returns_fallback() {
    let r = chain().parse(b"\x00\x01\x02garbage", 9999);
    assert_eq!(r.service, "unknown");
}

#[tokio::test]
async fn nsock_pool_timeout() {
    use uv_proto::nsock::EventPool;
    use uv_proto::nsock::IoEventKind;
    // Port 1 on localhost — should time out or be refused quickly
    let addr = "127.0.0.1:1".parse().unwrap();
    let mut pool = EventPool::new(200);
    pool.submit(addr, None);
    let events = pool.run().await;
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].kind,
        IoEventKind::Timeout | IoEventKind::Error(_)
    ));
}
