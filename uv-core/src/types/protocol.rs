use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Sctp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::Sctp => write!(f, "sctp"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceKind {
    Http,
    Https,
    Ssh,
    Ftp,
    Smtp,
    Dns,
    Rdp,
    Smb,
    Mysql,
    Postgres,
    Redis,
    Mongodb,
    Telnet,
    Unknown(String),
}

impl ServiceKind {
    pub fn from_port(port: u16, proto: Protocol) -> Self {
        match (port, proto) {
            (21, Protocol::Tcp) => ServiceKind::Ftp,
            (22, Protocol::Tcp) => ServiceKind::Ssh,
            (23, Protocol::Tcp) => ServiceKind::Telnet,
            (25, Protocol::Tcp) => ServiceKind::Smtp,
            (53, _) => ServiceKind::Dns,
            (80, Protocol::Tcp) => ServiceKind::Http,
            (443, Protocol::Tcp) => ServiceKind::Https,
            (445, Protocol::Tcp) => ServiceKind::Smb,
            (3306, Protocol::Tcp) => ServiceKind::Mysql,
            (3389, Protocol::Tcp) => ServiceKind::Rdp,
            (5432, Protocol::Tcp) => ServiceKind::Postgres,
            (6379, Protocol::Tcp) => ServiceKind::Redis,
            (27017, Protocol::Tcp) => ServiceKind::Mongodb,
            _ => ServiceKind::Unknown(format!("{}/{}", port, proto)),
        }
    }
}

impl std::fmt::Display for ServiceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceKind::Http => write!(f, "http"),
            ServiceKind::Https => write!(f, "https"),
            ServiceKind::Ssh => write!(f, "ssh"),
            ServiceKind::Ftp => write!(f, "ftp"),
            ServiceKind::Smtp => write!(f, "smtp"),
            ServiceKind::Dns => write!(f, "dns"),
            ServiceKind::Rdp => write!(f, "rdp"),
            ServiceKind::Smb => write!(f, "smb"),
            ServiceKind::Mysql => write!(f, "mysql"),
            ServiceKind::Postgres => write!(f, "postgres"),
            ServiceKind::Redis => write!(f, "redis"),
            ServiceKind::Mongodb => write!(f, "mongodb"),
            ServiceKind::Telnet => write!(f, "telnet"),
            ServiceKind::Unknown(s) => write!(f, "{s}"),
        }
    }
}
