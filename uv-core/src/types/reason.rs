// Port state reason — nmap portreasons.cc style.
// Records WHY a port was classified open/closed/filtered.

use serde::{Deserialize, Serialize};

/// The packet or event that caused the port state classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateReason {
    /// SYN-ACK received → open
    SynAck,
    /// RST received → closed
    Rst,
    /// ICMP port-unreachable (type=3, code=3) → closed
    IcmpPortUnreach,
    /// ICMP admin-prohibited (type=3, code=1/9/10/13) → filtered
    IcmpAdminProhibited,
    /// ICMP host-unreachable (type=3, code=1) → filtered
    IcmpHostUnreach,
    /// ICMP net-unreachable (type=3, code=0) → filtered
    IcmpNetUnreach,
    /// ICMP TTL exceeded (type=11) → filtered
    IcmpTtlExceeded,
    /// No response within timeout → filtered
    NoResponse,
    /// TCP connect() succeeded → open
    TcpConnect,
    /// TCP connection refused (RST at connect) → closed
    ConnRefused,
    /// SYN sent but no response → filtered
    SynNoResponse,
    /// ACK received (Window scan) → open
    AckWindow,
    /// SCTP INIT-ACK received → open
    SctpInitAck,
    /// SCTP ABORT received → closed
    SctpAbort,
    /// UDP response received → open
    UdpResponse,
    /// Unknown
    Unknown,
}

impl StateReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::SynAck => "syn-ack",
            Self::Rst => "rst",
            Self::IcmpPortUnreach => "icmp-port-unreach",
            Self::IcmpAdminProhibited => "admin-prohibited",
            Self::IcmpHostUnreach => "host-unreach",
            Self::IcmpNetUnreach => "net-unreach",
            Self::IcmpTtlExceeded => "ttl-exceeded",
            Self::NoResponse => "no-response",
            Self::TcpConnect => "syn-ack",
            Self::ConnRefused => "conn-refused",
            Self::SynNoResponse => "no-response",
            Self::AckWindow => "window",
            Self::SctpInitAck => "init-ack",
            Self::SctpAbort => "abort",
            Self::UdpResponse => "udp-response",
            Self::Unknown => "unknown",
        }
    }

    /// Returns true if this reason implies the port is open.
    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::SynAck
                | Self::TcpConnect
                | Self::AckWindow
                | Self::SctpInitAck
                | Self::UdpResponse
        )
    }

    /// Returns true if this reason implies the port is closed.
    pub fn is_closed(self) -> bool {
        matches!(
            self,
            Self::Rst | Self::IcmpPortUnreach | Self::ConnRefused | Self::SctpAbort
        )
    }

    /// From ICMP type+code pair.
    pub fn from_icmp(icmp_type: u8, icmp_code: u8) -> Self {
        match (icmp_type, icmp_code) {
            (3, 3) => Self::IcmpPortUnreach,
            (3, 0) => Self::IcmpNetUnreach,
            (3, 1) => Self::IcmpHostUnreach,
            (3, 1) | (3, 9) | (3, 10) | (3, 13) => Self::IcmpAdminProhibited,
            (11, _) => Self::IcmpTtlExceeded,
            _ => Self::Unknown,
        }
    }
}

impl std::fmt::Display for StateReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}
