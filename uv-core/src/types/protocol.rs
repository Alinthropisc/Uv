use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UvProtocol {
    Tcp,
    Udp,
    Icmp,
    Sctp,
}

impl std::fmt::Display for UvProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UvProtocol::Tcp => write!(f, "tcp"),
            UvProtocol::Udp => write!(f, "udp"),
            UvProtocol::Icmp => write!(f, "icmp"),
            UvProtocol::Sctp => write!(f, "sctp"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UvServiceKind {
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

impl UvServiceKind {
    pub fn from_port(port: u16, proto: UvProtocol) -> Self {
        match (port, proto) {
            (21, UvProtocol::Tcp) => UvServiceKind::Ftp,
            (22, UvProtocol::Tcp) => UvServiceKind::Ssh,
            (23, UvProtocol::Tcp) => UvServiceKind::Telnet,
            (25, UvProtocol::Tcp) => UvServiceKind::Smtp,
            (53, _) => UvServiceKind::Dns,
            (80, UvProtocol::Tcp) => UvServiceKind::Http,
            (443, UvProtocol::Tcp) => UvServiceKind::Https,
            (445, UvProtocol::Tcp) => UvServiceKind::Smb,
            (3306, UvProtocol::Tcp) => UvServiceKind::Mysql,
            (3389, UvProtocol::Tcp) => UvServiceKind::Rdp,
            (5432, UvProtocol::Tcp) => UvServiceKind::Postgres,
            (6379, UvProtocol::Tcp) => UvServiceKind::Redis,
            (27017, UvProtocol::Tcp) => UvServiceKind::Mongodb,
            _ => UvServiceKind::Unknown(format!("{}/{}", port, proto)),
        }
    }
}

impl std::fmt::Display for UvServiceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UvServiceKind::Http => write!(f, "http"),
            UvServiceKind::Https => write!(f, "https"),
            UvServiceKind::Ssh => write!(f, "ssh"),
            UvServiceKind::Ftp => write!(f, "ftp"),
            UvServiceKind::Smtp => write!(f, "smtp"),
            UvServiceKind::Dns => write!(f, "dns"),
            UvServiceKind::Rdp => write!(f, "rdp"),
            UvServiceKind::Smb => write!(f, "smb"),
            UvServiceKind::Mysql => write!(f, "mysql"),
            UvServiceKind::Postgres => write!(f, "postgres"),
            UvServiceKind::Redis => write!(f, "redis"),
            UvServiceKind::Mongodb => write!(f, "mongodb"),
            UvServiceKind::Telnet => write!(f, "telnet"),
            UvServiceKind::Unknown(s) => write!(f, "{s}"),
        }
    }
}