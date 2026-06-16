// Version detection — nmap-service-probes style.
// Each probe: send payload → match response with pattern → extract version string.
//
// Architecture: Strategy (VersionProbe trait) + Chain of Responsibility (ProbeSet).
// Ports are mapped to probe sets via port_matches(), mirroring nmap's Probe directive.

use std::net::IpAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Extracted service version info from a banner.
#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub service: &'static str,
    pub product: String,
    pub version: String,
    pub extra: Option<String>,
    pub cpe: Option<String>,
}

impl VersionInfo {
    pub fn new(
        service: &'static str,
        product: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            service,
            product: product.into(),
            version: version.into(),
            extra: None,
            cpe: None,
        }
    }
    pub fn with_cpe(mut self, cpe: impl Into<String>) -> Self {
        self.cpe = Some(cpe.into());
        self
    }
    pub fn with_extra(mut self, extra: impl Into<String>) -> Self {
        self.extra = Some(extra.into());
        self
    }
}

/// A single version probe: send payload, match response.
pub trait VersionProbe: Send + Sync {
    fn name(&self) -> &'static str;
    /// Ports this probe is sent to. Empty = try on all ports.
    fn port_matches(&self, port: u16) -> bool;
    /// Build the payload to send (None = just read banner, don't send anything).
    fn payload(&self) -> Option<&[u8]>;
    /// Attempt to extract version info from the raw response bytes.
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo>;
}

/// Chain of Responsibility — try probes in order, return first match.
pub struct ProbeSet {
    probes: Vec<Box<dyn VersionProbe>>,
    timeout_ms: u32,
}

impl ProbeSet {
    pub fn new(timeout_ms: u32) -> Self {
        Self {
            probes: Vec::new(),
            timeout_ms,
        }
    }

    pub fn add(mut self, p: impl VersionProbe + 'static) -> Self {
        self.probes.push(Box::new(p));
        self
    }

    /// Try all applicable probes against (ip, port). Returns first successful match.
    pub async fn detect(&self, ip: IpAddr, port: u16) -> Option<VersionInfo> {
        for probe in self.probes.iter().filter(|p| p.port_matches(port)) {
            if let Some(info) = self.run_probe(probe.as_ref(), ip, port).await {
                return Some(info);
            }
        }
        None
    }

    async fn run_probe(
        &self,
        probe: &dyn VersionProbe,
        ip: IpAddr,
        port: u16,
    ) -> Option<VersionInfo> {
        let addr = std::net::SocketAddr::new(ip, port);
        let dur = Duration::from_millis(self.timeout_ms as u64);

        let mut stream = match timeout(dur, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };

        if let Some(payload) = probe.payload() {
            if timeout(dur, stream.write_all(payload)).await.is_err() {
                return None;
            }
        }

        let mut buf = vec![0u8; 4096];
        let n = match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return None,
        };

        probe.extract(&buf[..n])
    }
}

// ─── Built-in probes ──────────────────────────────────────────────────────────

/// NULL probe — just read the banner (no payload sent). Works for FTP, SMTP, SSH.
pub struct NullProbe {
    name: &'static str,
    ports: &'static [u16],
    extractor: fn(&[u8]) -> Option<VersionInfo>,
}

impl VersionProbe for NullProbe {
    fn name(&self) -> &'static str {
        self.name
    }
    fn port_matches(&self, port: u16) -> bool {
        self.ports.is_empty() || self.ports.contains(&port)
    }
    fn payload(&self) -> Option<&[u8]> {
        None
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        (self.extractor)(banner)
    }
}

/// Generic HTTP probe — send GET / HTTP/1.0.
pub struct HttpProbe;

impl VersionProbe for HttpProbe {
    fn name(&self) -> &'static str {
        "http-get"
    }
    fn port_matches(&self, port: u16) -> bool {
        matches!(port, 80 | 8080 | 8000 | 8008 | 8888 | 8443 | 3000 | 5000)
    }
    fn payload(&self) -> Option<&[u8]> {
        Some(b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        let text = std::str::from_utf8(banner).ok()?;
        // HTTP/1.x 200 OK / Server: Apache/2.4.51 (Ubuntu)
        let server = text
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("server:"))?
            .splitn(2, ':')
            .nth(1)?
            .trim();
        // Split "Apache/2.4.51 (Ubuntu)" → product="Apache", version="2.4.51"
        let (product, version) = if let Some(slash) = server.find('/') {
            let prod = &server[..slash];
            let rest = &server[slash + 1..];
            let ver = rest.split_whitespace().next().unwrap_or(rest);
            (prod.to_string(), ver.to_string())
        } else {
            (server.to_string(), String::new())
        };
        Some(VersionInfo::new("http", product, version))
    }
}

/// SSH banner probe — SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
pub struct SshProbe;

impl VersionProbe for SshProbe {
    fn name(&self) -> &'static str {
        "ssh-banner"
    }
    fn port_matches(&self, _port: u16) -> bool {
        true
    }
    fn payload(&self) -> Option<&[u8]> {
        None
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        let text = std::str::from_utf8(banner).ok()?;
        // SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
        let line = text.lines().find(|l| l.starts_with("SSH-"))?;
        let parts: Vec<&str> = line.splitn(3, '-').collect();
        // parts[0]="SSH", parts[1]="2.0", parts[2]="OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        let software = parts.get(2).unwrap_or(&"");
        let (product, version) = if let Some(under) = software.find('_') {
            let prod = &software[..under];
            let ver_rest = &software[under + 1..];
            let ver = ver_rest.split_whitespace().next().unwrap_or(ver_rest);
            (prod.to_string(), ver.to_string())
        } else {
            (software.to_string(), String::new())
        };
        Some(
            VersionInfo::new("ssh", product, version.clone())
                .with_cpe(format!("cpe:/a:openbsd:openssh:{version}"))
                .with_extra(line.to_string()),
        )
    }
}

/// FTP banner probe — 220 ProFTPD 1.3.6 Server
pub struct FtpProbe;

impl VersionProbe for FtpProbe {
    fn name(&self) -> &'static str {
        "ftp-banner"
    }
    fn port_matches(&self, _port: u16) -> bool {
        true
    }
    fn payload(&self) -> Option<&[u8]> {
        None
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        let text = std::str::from_utf8(banner).ok()?;
        let line = text.lines().find(|l| l.starts_with("220"))?;
        // "220 ProFTPD 1.3.6 Server (Debian)"
        // "220 vsftpd 3.0.5"
        // "220 FileZilla Server 1.8.0"
        let body = line.trim_start_matches("220").trim();
        let parts: Vec<&str> = body.split_whitespace().collect();
        let product = parts.first().unwrap_or(&"").to_string();
        let version = parts.get(1).unwrap_or(&"").to_string();
        Some(VersionInfo::new("ftp", product, version))
    }
}

/// SMTP banner probe — 220 mail.example.com ESMTP Postfix
pub struct SmtpProbe;

impl VersionProbe for SmtpProbe {
    fn name(&self) -> &'static str {
        "smtp-banner"
    }
    fn port_matches(&self, port: u16) -> bool {
        matches!(port, 25 | 465 | 587 | 2525)
    }
    fn payload(&self) -> Option<&[u8]> {
        None
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        let text = std::str::from_utf8(banner).ok()?;
        let line = text.lines().find(|l| l.starts_with("220"))?;
        // "220 mail.example.com ESMTP Postfix (Ubuntu)"
        let tokens: Vec<&str> = line.split_whitespace().collect();
        // tokens[2] = "ESMTP", tokens[3] = "Postfix"
        let product = tokens.get(3).unwrap_or(&"SMTP").to_string();
        Some(VersionInfo::new("smtp", product, String::new()))
    }
}

/// MySQL banner probe (greeting packet starts with length + protocol version).
pub struct MysqlProbe;

impl VersionProbe for MysqlProbe {
    fn name(&self) -> &'static str {
        "mysql-greeting"
    }
    fn port_matches(&self, port: u16) -> bool {
        port == 3306
    }
    fn payload(&self) -> Option<&[u8]> {
        None
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        // MySQL protocol: 3-byte length + 1 seq + 1 protocol_version + null-terminated version
        if banner.len() < 6 {
            return None;
        }
        let proto_ver = banner[4];
        if proto_ver != 10 {
            return None;
        } // protocol v10 = MySQL 3.21+
          // version string starts at byte 5, null-terminated
        let ver_bytes = &banner[5..];
        let end = ver_bytes.iter().position(|&b| b == 0)?;
        let version = std::str::from_utf8(&ver_bytes[..end]).ok()?.to_string();
        Some(
            VersionInfo::new("mysql", "MySQL", version.clone())
                .with_cpe(format!("cpe:/a:mysql:mysql:{version}")),
        )
    }
}

/// Redis inline PING probe.
pub struct RedisProbe;

impl VersionProbe for RedisProbe {
    fn name(&self) -> &'static str {
        "redis-ping"
    }
    fn port_matches(&self, port: u16) -> bool {
        port == 6379
    }
    fn payload(&self) -> Option<&[u8]> {
        Some(b"*1\r\n$4\r\nINFO\r\n")
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        let text = std::str::from_utf8(banner).ok()?;
        // redis_version:7.0.11
        let ver_line = text.lines().find(|l| l.starts_with("redis_version:"))?;
        let version = ver_line.splitn(2, ':').nth(1)?.trim().to_string();
        Some(
            VersionInfo::new("redis", "Redis", version.clone())
                .with_cpe(format!("cpe:/a:redis:redis:{version}")),
        )
    }
}

/// PostgreSQL startup message — read the first error/notice to extract version.
pub struct PostgresProbe;

impl VersionProbe for PostgresProbe {
    fn name(&self) -> &'static str {
        "postgres-startup"
    }
    fn port_matches(&self, port: u16) -> bool {
        port == 5432
    }
    fn payload(&self) -> Option<&[u8]> {
        // StartupMessage: length(4) + protocol 196608 (3.0) + user\0postgres\0\0
        // Pre-built bytes for simplicity
        static MSG: &[u8] = b"\x00\x00\x00\x15\x00\x03\x00\x00user\x00postgres\x00\x00";
        Some(MSG)
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        // Server replies with 'E' (error) or 'R' (auth request).
        // The error message often contains the PG version: "PostgreSQL 14.2"
        let text = std::str::from_utf8(banner).ok()?;
        if let Some(pos) = text.find("PostgreSQL") {
            let rest = &text[pos + 10..]; // skip "PostgreSQL"
            let ver = rest
                .trim_start()
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches(|c: char| !c.is_ascii_digit() && c != '.');
            return Some(
                VersionInfo::new("postgres", "PostgreSQL", ver.to_string())
                    .with_cpe(format!("cpe:/a:postgresql:postgresql:{ver}")),
            );
        }
        None
    }
}

/// TLS/SSL record probe — send ClientHello, read ServerHello version.
pub struct TlsProbe;

impl VersionProbe for TlsProbe {
    fn name(&self) -> &'static str {
        "tls-hello"
    }
    fn port_matches(&self, port: u16) -> bool {
        matches!(port, 443 | 8443 | 465 | 993 | 995 | 636 | 3269 | 8883)
    }
    fn payload(&self) -> Option<&[u8]> {
        // Minimal TLS 1.2 ClientHello
        static HELLO: &[u8] = &[
            0x16, 0x03, 0x01, // TLS handshake, version 1.0 compat
            0x00, 0x2f, // length = 47
            0x01, // HandshakeType: ClientHello
            0x00, 0x00, 0x2b, // length
            0x03, 0x03, // client_version: TLS 1.2
            // 32 bytes random
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x00, // session ID length = 0
            0x00, 0x02, 0xc0,
            0x2b, // cipher suites: 1 x TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0x01, 0x00, // compression: null
            0x00, 0x00, // extensions length = 0
        ];
        Some(HELLO)
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        // ServerHello: 0x16 0x03 {ver_major} {ver_minor} ... 0x02 (ServerHello) ...
        if banner.len() < 6 {
            return None;
        }
        if banner[0] != 0x16 {
            return None;
        }
        let version = match (banner[1], banner[2]) {
            (0x03, 0x04) => "TLS 1.3",
            (0x03, 0x03) => "TLS 1.2",
            (0x03, 0x02) => "TLS 1.1",
            (0x03, 0x01) => "TLS 1.0",
            (0x03, 0x00) => "SSL 3.0",
            _ => return None,
        };
        Some(VersionInfo::new("ssl", "TLS", version.to_string()))
    }
}

/// Telnet banner — reads the initial IAC negotiation + greeting.
pub struct TelnetProbe;

impl VersionProbe for TelnetProbe {
    fn name(&self) -> &'static str {
        "telnet-banner"
    }
    fn port_matches(&self, port: u16) -> bool {
        port == 23
    }
    fn payload(&self) -> Option<&[u8]> {
        None
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        // Skip IAC bytes (0xff sequences), find printable text
        let text: String = banner
            .iter()
            .skip_while(|&&b| b == 0xff)
            .filter(|&&b| b >= 0x20 && b < 0x7f)
            .map(|&b| b as char)
            .collect();
        if text.is_empty() {
            return None;
        }
        let product = text.lines().next().unwrap_or("").trim().to_string();
        Some(VersionInfo::new("telnet", product, String::new()))
    }
}

/// RDP probe — send a TPKT + X.224 CR TPDU, parse server response class.
pub struct RdpProbe;

impl VersionProbe for RdpProbe {
    fn name(&self) -> &'static str {
        "rdp-init"
    }
    fn port_matches(&self, port: u16) -> bool {
        port == 3389 || port == 3388
    }
    fn payload(&self) -> Option<&[u8]> {
        // TPKT header (4) + X.224 Connection Request TPDU
        // "Cookie: mstshash=uv\r\n"
        static PKT: &[u8] = &[
            0x03, 0x00, 0x00, 0x2b, // TPKT: version=3, reserved=0, length=43
            0x26, // X.224 TPDU length=38
            0xe0, // CR TPDU code
            0x00, 0x00, // dst ref
            0x00, 0x00, // src ref
            0x00, // class/options
            // "Cookie: mstshash=uv\r\n"
            0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x3a, 0x20, 0x6d, 0x73, 0x74, 0x73, 0x68, 0x61,
            0x73, 0x68, 0x3d, 0x75, 0x76, 0x0d, 0x0a,
            // rdpNegReq: type=1, flags=0, length=8, protocols=PROTOCOL_SSL(1)
            0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        Some(PKT)
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        // TPKT response: bytes[5]=CC TPDU (0xd0), bytes[11]=rdpNegResp type
        if banner.len() < 12 {
            return None;
        }
        if banner[5] != 0xd0 {
            return None;
        } // CC TPDU
          // rdpNegResp type byte at offset 11
        let proto = match banner.get(15).copied().unwrap_or(0) {
            0x01 => "SSL/TLS",
            0x02 => "CredSSP",
            0x08 => "RDSTLS",
            _ => "RDP",
        };
        Some(VersionInfo::new("rdp", "Microsoft RDP", proto.to_string()))
    }
}

/// MongoDB wire protocol probe — send OP_QUERY isMaster.
pub struct MongoProbe;

impl VersionProbe for MongoProbe {
    fn name(&self) -> &'static str {
        "mongodb-ismaster"
    }
    fn port_matches(&self, port: u16) -> bool {
        port == 27017 || port == 27018 || port == 27019
    }
    fn payload(&self) -> Option<&[u8]> {
        // Minimal OP_QUERY: { isMaster: 1 }
        // Wire protocol: MsgHeader(16) + flags(4) + fullCollectionName + skip(4) + returnN(4) + doc
        // Pre-built for admin.$cmd isMaster query
        static MSG: &[u8] = &[
            // MsgHeader: total_len(4) reqId(4) responseTo(4) opCode=OP_QUERY(4=2004)
            0x48, 0x00, 0x00, 0x00, // total length = 72
            0x01, 0x00, 0x00, 0x00, // requestID
            0x00, 0x00, 0x00, 0x00, // responseTo
            0xd4, 0x07, 0x00, 0x00, // opCode = 2004 (OP_QUERY)
            0x00, 0x00, 0x00, 0x00, // flags
            // fullCollectionName: "admin.$cmd\0"
            0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, 0x00, 0x00, 0x00,
            0x00, // numberToSkip
            0x01, 0x00, 0x00, 0x00, // numberToReturn = 1
            // BSON doc: { isMaster: 1 }
            0x13, 0x00, 0x00, 0x00, // doc length = 19
            0x10, // type: int32
            0x69, 0x73, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, // "isMaster\0"
            0x01, 0x00, 0x00, 0x00, // value = 1
            0x00, // end of doc
        ];
        Some(MSG)
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        // OP_REPLY response: skip MsgHeader(16) + responseFlags(4) + cursorID(8) + start(4) + count(4) = 36
        // Then BSON doc — look for "maxWireVersion" or "version" strings
        if banner.len() < 36 {
            return None;
        }
        let text = std::str::from_utf8(banner).unwrap_or("");
        // Look for version string like "4.4.6" in the BSON blob
        if text.contains("ismaster") || banner[16..].windows(8).any(|w| w == b"maxWire") {
            Some(VersionInfo::new("mongodb", "MongoDB", String::new()))
        } else {
            None
        }
    }
}

/// AMQP/RabbitMQ — send AMQP0-9-1 header, parse Connection.Start.
pub struct AmqpProbe;

impl VersionProbe for AmqpProbe {
    fn name(&self) -> &'static str {
        "amqp-header"
    }
    fn port_matches(&self, port: u16) -> bool {
        port == 5672 || port == 5671
    }
    fn payload(&self) -> Option<&[u8]> {
        // AMQP 0-9-1 protocol header
        Some(b"AMQP\x00\x00\x09\x01")
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        // Server replies with Connection.Start frame (type=1, channel=0)
        // Frame: type(1) + channel(2) + size(4) + payload + 0xce
        if banner.len() < 7 || banner[0] != 1 {
            return None;
        }
        // payload starts at byte 7, contains AMQP table with "version" fields
        let text = std::str::from_utf8(banner).unwrap_or("");
        // RabbitMQ sends "RabbitMQ" in server-properties
        let product = if text.contains("RabbitMQ") {
            "RabbitMQ"
        } else if text.contains("ActiveMQ") {
            "ActiveMQ"
        } else {
            "AMQP broker"
        };
        // Extract version string if present: look for "3\x2e" pattern (e.g. "3.12.0")
        let version = banner
            .windows(5)
            .find(|w| w.iter().filter(|&&b| b == b'.').count() == 2 && w[0].is_ascii_digit())
            .and_then(|w| std::str::from_utf8(w).ok())
            .unwrap_or("")
            .to_string();
        Some(VersionInfo::new("amqp", product, version))
    }
}

/// LDAP — send anonymous BindRequest, detect server type from response.
pub struct LdapProbe;

impl VersionProbe for LdapProbe {
    fn name(&self) -> &'static str {
        "ldap-bind"
    }
    fn port_matches(&self, port: u16) -> bool {
        port == 389 || port == 636 || port == 3268
    }
    fn payload(&self) -> Option<&[u8]> {
        // Minimal LDAP BindRequest: messageID=1, version=3, dn="", simple auth=""
        // BER encoding
        static MSG: &[u8] = &[
            0x30, 0x0c, // SEQUENCE, length=12
            0x02, 0x01, 0x01, // INTEGER messageID=1
            0x60, 0x07, // APPLICATION 0 (BindRequest), length=7
            0x02, 0x01, 0x03, // INTEGER version=3
            0x04, 0x00, // OCTET STRING dn="" (empty)
            0x80, 0x00, // [0] simple="" (empty password)
        ];
        Some(MSG)
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        // BindResponse: SEQUENCE → messageID → APPLICATION 1 → resultCode
        // resultCode 0 = success (anonymous bind allowed), 49 = invalidCredentials (server exists)
        if banner.len() < 7 {
            return None;
        }
        if banner[0] != 0x30 {
            return None;
        } // must be SEQUENCE
          // Find APPLICATION 1 tag (0x61 = BindResponse)
        let has_bind_resp = banner.windows(1).any(|w| w[0] == 0x61);
        if !has_bind_resp {
            return None;
        }
        // Check result code byte
        let result_code = banner
            .iter()
            .position(|&b| b == 0x61)
            .and_then(|pos| banner.get(pos + 4).copied());
        let detail = match result_code {
            Some(0) => "anonymous bind allowed",
            Some(49) => "auth required",
            Some(32) => "no such object",
            _ => "responding",
        };
        Some(VersionInfo::new("ldap", "LDAP", detail.to_string()))
    }
}

/// Kafka — send ApiVersions request, read response.
pub struct KafkaProbe;

impl VersionProbe for KafkaProbe {
    fn name(&self) -> &'static str {
        "kafka-apiversions"
    }
    fn port_matches(&self, port: u16) -> bool {
        port == 9092 || port == 9093
    }
    fn payload(&self) -> Option<&[u8]> {
        // ApiVersions Request v0: length(4) + api_key(2)=18 + api_version(2)=0 + correlation(4) + client_id(2)=-1
        static MSG: &[u8] = &[
            0x00, 0x00, 0x00, 0x0a, // length=10
            0x00, 0x12, // api_key=18 (ApiVersions)
            0x00, 0x00, // api_version=0
            0x00, 0x00, 0x00, 0x01, // correlation_id=1
            0xff, 0xff, // client_id length=-1 (null)
        ];
        Some(MSG)
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        if banner.len() < 8 {
            return None;
        }
        // ApiVersions response starts with correlation_id(4) + error_code(2)
        let error_code = u16::from_be_bytes([banner[4], banner[5]]);
        if error_code == 0 || error_code == 35 {
            // 0=OK, 35=UNSUPPORTED_VERSION — both mean Kafka is there
            Some(VersionInfo::new("kafka", "Apache Kafka", String::new()))
        } else {
            None
        }
    }
}

/// Elasticsearch HTTP probe — GET / returns cluster info JSON.
pub struct ElasticsearchProbe;

impl VersionProbe for ElasticsearchProbe {
    fn name(&self) -> &'static str {
        "elasticsearch-info"
    }
    fn port_matches(&self, port: u16) -> bool {
        port == 9200 || port == 9300
    }
    fn payload(&self) -> Option<&[u8]> {
        Some(b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        let text = std::str::from_utf8(banner).ok()?;
        if !text.contains("\"tagline\"") && !text.contains("You Know, for Search") {
            return None;
        }
        let version = if let Some(pos) = text.find("\"number\"") {
            let rest = &text[pos + 8..];
            rest.trim_start_matches(|c: char| !c.is_ascii_digit() && c != '"')
                .trim_matches('"')
                .split('"')
                .next()
                .unwrap_or("")
                .to_string()
        } else {
            String::new()
        };
        Some(VersionInfo::new("elasticsearch", "Elasticsearch", version))
    }
}

/// ZooKeeper — send `mntr` 4-letter command.
pub struct ZookeeperProbe;

impl VersionProbe for ZookeeperProbe {
    fn name(&self) -> &'static str {
        "zookeeper-mntr"
    }
    fn port_matches(&self, port: u16) -> bool {
        port == 2181 || port == 2182
    }
    fn payload(&self) -> Option<&[u8]> {
        Some(b"mntr")
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        let text = std::str::from_utf8(banner).ok()?;
        let ver_line = text.lines().find(|l| l.starts_with("zk_version"))?;
        let version = ver_line.splitn(2, '\t').nth(1).unwrap_or("").trim();
        let short = version.split('-').next().unwrap_or(version);
        Some(VersionInfo::new(
            "zookeeper",
            "Apache ZooKeeper",
            short.to_string(),
        ))
    }
}

/// gRPC — send HTTP/2 connection preface + SETTINGS frame, check for gRPC headers.
pub struct GrpcProbe;

impl VersionProbe for GrpcProbe {
    fn name(&self) -> &'static str {
        "grpc-preface"
    }
    fn port_matches(&self, port: u16) -> bool {
        matches!(port, 50051 | 50052 | 9090 | 8080)
    }
    fn payload(&self) -> Option<&[u8]> {
        // HTTP/2 connection preface + empty SETTINGS frame
        static PREFACE: &[u8] =
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";
        Some(PREFACE)
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        // HTTP/2 server responds with SETTINGS frame: 9-byte header, type=0x04
        if banner.len() >= 9 && banner[3] == 0x04 {
            Some(VersionInfo::new("grpc", "gRPC/HTTP2", String::new()))
        } else if banner.windows(8).any(|w| w == b"grpc-sta") {
            Some(VersionInfo::new("grpc", "gRPC", String::new()))
        } else {
            None
        }
    }
}

/// WinRM — HTTP probe on 5985/5986, look for WSMAN/wsman service.
pub struct WinRmProbe;

impl VersionProbe for WinRmProbe {
    fn name(&self) -> &'static str {
        "winrm-http"
    }
    fn port_matches(&self, port: u16) -> bool {
        port == 5985 || port == 5986
    }
    fn payload(&self) -> Option<&[u8]> {
        Some(b"GET /wsman HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        let text = std::str::from_utf8(banner).ok()?;
        if text.contains("WSMAN") || text.contains("wsman") || text.contains("WSManFault") {
            Some(VersionInfo::new("winrm", "Microsoft WinRM", String::new()))
        } else {
            None
        }
    }
}

/// Oracle TNS probe — send Connect packet, parse response.
pub struct OracleProbe;

impl VersionProbe for OracleProbe {
    fn name(&self) -> &'static str {
        "oracle-tns"
    }
    fn port_matches(&self, port: u16) -> bool {
        port == 1521 || port == 1522
    }
    fn payload(&self) -> Option<&[u8]> {
        // Minimal TNS Connect packet
        static TNS: &[u8] = &[
            0x00, 0x3a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x3c, 0x01, 0x2c, 0x00, 0x06,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        Some(TNS)
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        // TNS response type byte at offset 4: 2=ACCEPT, 4=REFUSE, 5=REDIRECT
        if banner.len() < 8 {
            return None;
        }
        match banner[4] {
            2 | 4 | 5 => Some(VersionInfo::new("oracle", "Oracle DB", String::new())),
            _ => None,
        }
    }
}

/// MSSQL TDS probe — send pre-login packet, parse version.
pub struct MssqlProbe;

impl VersionProbe for MssqlProbe {
    fn name(&self) -> &'static str {
        "mssql-prelogin"
    }
    fn port_matches(&self, port: u16) -> bool {
        port == 1433 || port == 1434
    }
    fn payload(&self) -> Option<&[u8]> {
        // TDS7 PreLogin packet
        static PRELOGIN: &[u8] = &[
            0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00, // TDS header
            0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20, // options
            0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03, 0x00, 0x22, 0x00, 0x04, 0x04, 0x00,
            0x26, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        Some(PRELOGIN)
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        if banner.len() < 8 {
            return None;
        }
        // TDS PreLoginResponse type byte = 0x04
        if banner[0] != 0x04 {
            return None;
        }
        // Version bytes at offset 8..12 in payload (after 8-byte TDS header)
        let version = if banner.len() >= 14 {
            format!(
                "{}.{}.{}",
                banner[8],
                banner[9],
                u16::from_be_bytes([banner[10], banner[11]])
            )
        } else {
            String::new()
        };
        Some(VersionInfo::new("mssql", "Microsoft SQL Server", version))
    }
}

/// Cassandra native protocol — send OPTIONS request, parse SUPPORTED response.
pub struct CassandraProbe;

impl VersionProbe for CassandraProbe {
    fn name(&self) -> &'static str {
        "cassandra-options"
    }
    fn port_matches(&self, port: u16) -> bool {
        port == 9042 || port == 9142
    }
    fn payload(&self) -> Option<&[u8]> {
        // CQL native protocol v4 OPTIONS frame
        // version(1) + flags(1) + stream(2) + opcode(1)=5 + length(4)
        static OPT: &[u8] = &[0x04, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00];
        Some(OPT)
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        if banner.len() < 9 {
            return None;
        }
        // SUPPORTED opcode = 0x06
        if banner[4] == 0x06 || (banner[0] & 0x7f) == 4 {
            Some(VersionInfo::new(
                "cassandra",
                "Apache Cassandra",
                String::new(),
            ))
        } else {
            None
        }
    }
}

/// Memcached stats probe (TCP).
pub struct MemcachedProbe;

impl VersionProbe for MemcachedProbe {
    fn name(&self) -> &'static str {
        "memcached-stats"
    }
    fn port_matches(&self, port: u16) -> bool {
        port == 11211
    }
    fn payload(&self) -> Option<&[u8]> {
        Some(b"stats\r\n")
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        let text = std::str::from_utf8(banner).ok()?;
        let ver_line = text.lines().find(|l| l.starts_with("STAT version"))?;
        let version = ver_line.split_whitespace().nth(2).unwrap_or("").to_string();
        Some(VersionInfo::new("memcached", "Memcached", version))
    }
}

/// IMAP probe — read greeting, extract server name/version.
pub struct ImapProbe;

impl VersionProbe for ImapProbe {
    fn name(&self) -> &'static str {
        "imap-greeting"
    }
    fn port_matches(&self, port: u16) -> bool {
        matches!(port, 143 | 993 | 220)
    }
    fn payload(&self) -> Option<&[u8]> {
        None
    }
    fn extract(&self, banner: &[u8]) -> Option<VersionInfo> {
        let text = std::str::from_utf8(banner).ok()?;
        let line = text.lines().find(|l| l.contains("* OK"))?;
        // "* OK Dovecot ready." or "* OK [CAPABILITY ...] Microsoft Exchange"
        let product = if line.contains("Dovecot") {
            "Dovecot"
        } else if line.contains("Courier") {
            "Courier"
        } else if line.contains("Exchange") {
            "Microsoft Exchange"
        } else if line.contains("Cyrus") {
            "Cyrus"
        } else {
            "IMAP"
        };
        Some(VersionInfo::new("imap", product, String::new()))
    }
}

/// Build the default ProbeSet with all built-in probes.
pub fn default_probe_set(timeout_ms: u32) -> ProbeSet {
    ProbeSet::new(timeout_ms)
        .add(SshProbe)
        .add(FtpProbe)
        .add(SmtpProbe)
        .add(HttpProbe)
        .add(MysqlProbe)
        .add(RedisProbe)
        .add(PostgresProbe)
        .add(TlsProbe)
        .add(TelnetProbe)
        .add(RdpProbe)
        .add(MongoProbe)
        .add(AmqpProbe)
        .add(LdapProbe)
        .add(KafkaProbe)
        .add(ElasticsearchProbe)
        .add(ZookeeperProbe)
        .add(GrpcProbe)
        .add(WinRmProbe)
        .add(OracleProbe)
        .add(MssqlProbe)
        .add(CassandraProbe)
        .add(MemcachedProbe)
        .add(ImapProbe)
}
