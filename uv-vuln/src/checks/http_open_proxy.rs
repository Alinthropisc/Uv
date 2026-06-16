// HTTP open proxy check — connect through the host to an external IP.
// Mirrors nmap http-open-proxy script.

use crate::engine::{Checker, VulnResult, VulnSeverity};
use async_trait::async_trait;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

pub struct HttpOpenProxy;

#[async_trait]
impl Checker for HttpOpenProxy {
    fn name(&self) -> &'static str {
        "http-open-proxy"
    }
    fn ports(&self) -> &'static [u16] {
        &[80, 81, 3128, 8080, 8118, 8888, 9050]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        let sa = SocketAddr::new(ip, port);
        let result = tokio::task::spawn_blocking(move || probe(sa)).await;
        match result {
            Ok(true) => VulnResult::vuln(
                "http-open-proxy",
                VulnSeverity::High,
                "HTTP CONNECT proxy allows unrestricted tunnelling",
            ),
            _ => VulnResult::safe("http-open-proxy"),
        }
    }
}

fn probe(sa: SocketAddr) -> bool {
    let timeout = Duration::from_secs(5);
    let stream = match TcpStream::connect_timeout(&sa, timeout) {
        Ok(s) => s,
        Err(_) => return false,
    };
    stream.set_read_timeout(Some(Duration::from_secs(4))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(4))).ok();

    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;

    // Try CONNECT to a well-known IP:port (google DNS)
    let req = b"CONNECT 8.8.8.8:53 HTTP/1.0\r\nHost: 8.8.8.8:53\r\n\r\n";
    if writer.write_all(req).is_err() {
        return false;
    }

    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return false;
    }

    // 200 Connection established = open proxy
    line.contains("200")
}
