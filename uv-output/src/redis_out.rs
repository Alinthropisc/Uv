// Redis output — masscan out-redis.c style.
// Publishes scan results to a Redis channel using RESP protocol (no external crate needed).
// Each open port is published as: PUBLISH uv:results "<ip>,<port>,<proto>,<service>"

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use uv_core::types::port::PortState;
use uv_core::types::result::ScanResult;

pub struct RedisPublisher {
    host: String,
    port: u16,
    channel: String,
    password: Option<String>,
}

impl RedisPublisher {
    pub fn new(host: impl Into<String>, port: u16, channel: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            channel: channel.into(),
            password: None,
        }
    }

    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Publish all open ports from a ScanResult to Redis.
    pub fn publish(&self, result: &ScanResult) -> std::io::Result<usize> {
        let addr = format!("{}:{}", self.host, self.port);
        let mut stream =
            TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;

        // AUTH if needed
        if let Some(ref pw) = self.password {
            let cmd = resp_cmd(&["AUTH", pw]);
            stream.write_all(cmd.as_bytes())?;
            read_resp_reply(&mut stream)?;
        }

        let mut count = 0usize;
        for host in &result.hosts {
            for port in host.ports.iter().filter(|p| p.state == PortState::Open) {
                let svc = port
                    .service
                    .as_ref()
                    .map(|s| s.service.to_string())
                    .unwrap_or_else(|| "unknown".into());
                let msg = format!("{},{},{},{}", host.addr, port.port.0, port.proto, svc);
                let cmd = resp_cmd(&["PUBLISH", &self.channel, &msg]);
                stream.write_all(cmd.as_bytes())?;
                read_resp_reply(&mut stream)?;
                count += 1;
            }
        }

        // Send scan summary
        let summary = format!(
            "SCAN_DONE,hosts={},open={},duration_ms={}",
            result.hosts.len(),
            result.open_count(),
            result.duration_ms
        );
        let cmd = resp_cmd(&["PUBLISH", &self.channel, &summary]);
        stream.write_all(cmd.as_bytes())?;
        read_resp_reply(&mut stream)?;

        Ok(count)
    }

    /// Stream a single open port result to Redis immediately (call from pipeline).
    pub fn publish_one(
        stream: &mut TcpStream,
        channel: &str,
        ip: &str,
        port: u16,
        proto: &str,
        service: &str,
    ) -> std::io::Result<()> {
        let msg = format!("{},{},{},{}", ip, port, proto, service);
        let cmd = resp_cmd(&["PUBLISH", channel, &msg]);
        stream.write_all(cmd.as_bytes())?;
        read_resp_reply(stream)?;
        Ok(())
    }
}

/// Build a RESP (Redis Serialization Protocol) command string.
fn resp_cmd(parts: &[&str]) -> String {
    let mut out = format!("*{}\r\n", parts.len());
    for part in parts {
        out.push_str(&format!("${}\r\n{}\r\n", part.len(), part));
    }
    out
}

/// Read and discard one RESP reply ("+OK", ":N", "-ERR ...", etc.).
fn read_resp_reply(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = [0u8; 256];
    stream.read(&mut buf)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resp_format() {
        let cmd = resp_cmd(&["PUBLISH", "chan", "hello"]);
        assert!(cmd.starts_with("*3\r\n"));
        assert!(cmd.contains("$7\r\nPUBLISH\r\n"));
    }
}
