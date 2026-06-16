// Safe wrapper over proto/svcmatch.c — Facade pattern.
// Falls back to pure-Rust table when C layer not linked.

/// Service database — wraps svcmatch C table via pure-Rust mirror.
pub struct SvcDb;

impl SvcDb {
    pub fn new() -> Self {
        Self
    }

    /// Service name for port/proto (6=TCP, 17=UDP).
    pub fn name(&self, port: u16, proto: u8) -> &'static str {
        match (port, proto) {
            (21, 6) => "ftp",
            (22, 6) => "ssh",
            (23, 6) => "telnet",
            (25, 6) => "smtp",
            (53, _) => "dns",
            (80, 6) => "http",
            (110, 6) => "pop3",
            (123, 17) => "ntp",
            (143, 6) => "imap",
            (443, 6) => "https",
            (445, 6) => "smb",
            (465, 6) => "smtps",
            (993, 6) => "imaps",
            (995, 6) => "pop3s",
            (1433, 6) => "mssql",
            (3306, 6) => "mysql",
            (3389, 6) => "rdp",
            (5432, 6) => "postgres",
            (5900, 6) => "vnc",
            (6379, 6) => "redis",
            (8080, 6) => "http-alt",
            (8443, 6) => "https-alt",
            (9200, 6) => "elastic",
            (27017, 6) => "mongodb",
            _ => "unknown",
        }
    }

    /// Match banner bytes → service name.
    pub fn match_banner(&self, banner: &[u8], port: u16, proto: u8) -> &'static str {
        if banner.starts_with(b"SSH-") {
            return "ssh";
        }
        if banner.starts_with(b"HTTP/") {
            return "http";
        }
        if banner.starts_with(b"220 ") {
            return if port == 21 { "ftp" } else { "smtp" };
        }
        if banner.starts_with(b"+OK") {
            return "pop3";
        }
        if banner.starts_with(b"* OK") {
            return "imap";
        }
        if banner.starts_with(b"-ERR") {
            return "redis";
        }
        if banner.starts_with(b"RFB ") {
            return "vnc";
        }
        if banner.len() >= 3 && banner[0] == 0x16 && banner[1] == 0x03 {
            return "tls";
        }
        self.name(port, proto)
    }
}

impl Default for SvcDb {
    fn default() -> Self {
        Self::new()
    }
}
