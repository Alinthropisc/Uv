// Anonymous FTP login check — nmap ftp-anon script equivalent.
// Try USER anonymous / PASS anonymous@; check for 230 (Login successful).

use crate::engine::{Checker, VulnResult, VulnSeverity};
use async_trait::async_trait;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

pub struct AnonFtp;

#[async_trait]
impl Checker for AnonFtp {
    fn name(&self) -> &'static str {
        "ftp-anon"
    }
    fn ports(&self) -> &'static [u16] {
        &[21, 990]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        let sa = SocketAddr::new(ip, port);
        let result = tokio::task::spawn_blocking(move || probe(sa)).await;
        match result {
            Ok(Some(banner)) => VulnResult::vuln(
                "ftp-anon",
                VulnSeverity::Medium,
                format!("Anonymous FTP login allowed — {banner}"),
            ),
            _ => VulnResult::safe("ftp-anon"),
        }
    }
}

fn probe(sa: SocketAddr) -> Option<String> {
    let timeout = Duration::from_secs(5);
    let stream = TcpStream::connect_timeout(&sa, timeout).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(4))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(4))).ok();

    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut writer = stream;
    let mut line = String::new();

    // Read banner
    reader.read_line(&mut line).ok()?;
    if !line.starts_with("220") {
        return None;
    }
    let banner = line.trim().to_string();
    line.clear();

    // Send USER anonymous
    writer.write_all(b"USER anonymous\r\n").ok()?;
    reader.read_line(&mut line).ok()?;
    // 331 = Password required, 230 = logged in directly
    let need_pass = line.starts_with("331");
    let logged_in = line.starts_with("230");
    line.clear();

    if need_pass {
        writer.write_all(b"PASS anonymous@\r\n").ok()?;
        reader.read_line(&mut line).ok()?;
        if line.starts_with("230") {
            return Some(banner);
        }
    } else if logged_in {
        return Some(banner);
    }
    None
}
