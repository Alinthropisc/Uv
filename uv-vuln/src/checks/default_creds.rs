// Default credentials check — tries vendor default username/password combos
// against Telnet, HTTP Basic, and FTP endpoints.
// Covers: admin/admin, admin/password, root/root, root/(empty), guest/guest.

use crate::engine::{Checker, VulnResult, VulnSeverity};
use async_trait::async_trait;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

static DEFAULT_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", ""),
    ("root", "root"),
    ("root", "password"),
    ("root", ""),
    ("guest", "guest"),
    ("guest", ""),
    ("user", "user"),
    ("administrator", "administrator"),
    ("admin", "admin123"),
    ("admin", "12345"),
    ("ubnt", "ubnt"),           // Ubiquiti
    ("pi", "raspberry"),        // Raspberry Pi
    ("cisco", "cisco"),         // Cisco
    ("enable", "enable"),       // Cisco enable
    ("netscreen", "netscreen"), // Juniper
];

pub struct DefaultCreds {
    timeout_ms: u32,
}

impl DefaultCreds {
    pub fn new() -> Self {
        Self { timeout_ms: 3000 }
    }
    pub fn with_timeout(mut self, ms: u32) -> Self {
        self.timeout_ms = ms;
        self
    }
}

impl Default for DefaultCreds {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Checker for DefaultCreds {
    fn name(&self) -> &'static str {
        "default-creds"
    }
    fn ports(&self) -> &'static [u16] {
        &[21, 23, 80, 8080, 8443, 443]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        let sa = SocketAddr::new(ip, port);
        let timeout_ms = self.timeout_ms;
        let result = tokio::task::spawn_blocking(move || match port {
            21 => check_ftp(sa, timeout_ms),
            23 => check_telnet(sa, timeout_ms),
            80 | 8080 | 443 | 8443 => check_http_basic(sa, timeout_ms),
            _ => None,
        })
        .await;

        match result {
            Ok(Some((user, pass))) => VulnResult::vuln(
                "default-creds",
                VulnSeverity::Critical,
                format!("Default credentials work: {user}:{pass}"),
            ),
            _ => VulnResult::safe("default-creds"),
        }
    }
}

fn check_ftp(sa: SocketAddr, timeout_ms: u32) -> Option<(String, String)> {
    let timeout = Duration::from_millis(timeout_ms as u64);
    for (user, pass) in DEFAULT_CREDS {
        let stream = TcpStream::connect_timeout(&sa, timeout).ok()?;
        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();
        let mut reader = BufReader::new(stream.try_clone().ok()?);
        let mut writer = stream;
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        if !line.starts_with("220") {
            break;
        }
        line.clear();
        let _ = writer.write_all(format!("USER {user}\r\n").as_bytes());
        reader.read_line(&mut line).ok()?;
        line.clear();
        let _ = writer.write_all(format!("PASS {pass}\r\n").as_bytes());
        reader.read_line(&mut line).ok()?;
        if line.starts_with("230") {
            return Some((user.to_string(), pass.to_string()));
        }
    }
    None
}

fn check_telnet(sa: SocketAddr, timeout_ms: u32) -> Option<(String, String)> {
    // Simplified: connect and look for login prompt, send creds, check for shell prompt
    let timeout = Duration::from_millis(timeout_ms as u64);
    for (user, pass) in DEFAULT_CREDS {
        let mut stream = TcpStream::connect_timeout(&sa, timeout).ok()?;
        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();
        let mut buf = [0u8; 256];
        // skip IAC negotiation
        let _ = stream.read(&mut buf);
        let banner = String::from_utf8_lossy(&buf).to_lowercase();
        if !banner.contains("login") && !banner.contains("username") {
            break;
        }
        let _ = stream.write_all(format!("{user}\r\n").as_bytes());
        let _ = stream.read(&mut buf);
        let _ = stream.write_all(format!("{pass}\r\n").as_bytes());
        let _ = stream.read(&mut buf);
        let resp = String::from_utf8_lossy(&buf).to_lowercase();
        // Shell prompts: $, #, >, or lack of "incorrect"/"failed"
        if resp.contains('#') || resp.contains('$') || resp.contains('>') {
            return Some((user.to_string(), pass.to_string()));
        }
    }
    None
}

fn check_http_basic(sa: SocketAddr, timeout_ms: u32) -> Option<(String, String)> {
    let timeout = Duration::from_millis(timeout_ms as u64);
    for (user, pass) in DEFAULT_CREDS {
        let mut stream = TcpStream::connect_timeout(&sa, timeout).ok()?;
        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();
        // Build Basic auth header
        let creds = base64_encode(format!("{user}:{pass}").as_bytes());
        let req = format!("GET / HTTP/1.0\r\nHost: {sa}\r\nAuthorization: Basic {creds}\r\n\r\n");
        stream.write_all(req.as_bytes()).ok()?;
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        // 200 OK (not 401) = logged in with these creds
        if line.contains("200") {
            return Some((user.to_string(), pass.to_string()));
        }
    }
    None
}

fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < input.len() {
            input[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < input.len() {
            input[i + 2] as u32
        } else {
            0
        };
        out.push(CHARS[((b0 >> 2) & 0x3f) as usize] as char);
        out.push(CHARS[(((b0 << 4) | (b1 >> 4)) & 0x3f) as usize] as char);
        out.push(if i + 1 < input.len() {
            CHARS[(((b1 << 2) | (b2 >> 6)) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if i + 2 < input.len() {
            CHARS[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
        i += 3;
    }
    out
}
