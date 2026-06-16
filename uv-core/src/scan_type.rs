// Scan type enum — mirrors nmap scan mode flags.
// Raw-socket modes (SYN/NULL/FIN/Xmas/ACK/SCTP) need root; connect/udp don't.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ScanType {
    /// TCP connect() — works without root. Default for non-privileged users.
    #[default]
    TcpConnect,
    /// SYN stealth — raw socket SYN only, never completes handshake (-sS).
    SynStealth,
    /// UDP scan — send UDP probe, wait for ICMP port-unreach or response (-sU).
    Udp,
    /// NULL scan — TCP with no flags set (-sN). Bypasses some stateless firewalls.
    Null,
    /// FIN scan — TCP FIN only (-sF).
    Fin,
    /// Xmas scan — FIN+PSH+URG (-sX). Named for "lit up like a Christmas tree".
    Xmas,
    /// ACK scan — maps firewall rulesets, doesn't determine open/closed (-sA).
    Ack,
    /// Window scan — like ACK but uses TCP window field to infer state (-sW).
    Window,
    /// Ping sweep — ICMP echo + TCP ACK to detect live hosts (-sn).
    PingSweep,
    /// SCTP INIT scan — sends SCTP INIT chunk, INIT-ACK=open, ABORT=closed (-sY).
    SctpInit,
    /// SCTP COOKIE-ECHO scan — bypasses stateless firewalls that pass COOKIE-ECHO (-sZ).
    SctpCookieEcho,
    /// Idle/zombie scan — uses a third-party zombie host's IP ID to infer port state (-sI).
    Idle,
    /// IP protocol scan — iterates IP protocol numbers instead of ports (-sO).
    IpProto,
}

impl ScanType {
    pub fn needs_root(self) -> bool {
        matches!(
            self,
            Self::SynStealth
                | Self::Null
                | Self::Fin
                | Self::Xmas
                | Self::Ack
                | Self::Window
                | Self::PingSweep
                | Self::SctpInit
                | Self::SctpCookieEcho
                | Self::Idle
                | Self::IpProto
        )
    }

    pub fn is_tcp(self) -> bool {
        !matches!(
            self,
            Self::Udp | Self::PingSweep | Self::SctpInit | Self::SctpCookieEcho
        )
    }

    pub fn is_sctp(self) -> bool {
        matches!(self, Self::SctpInit | Self::SctpCookieEcho)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::TcpConnect => "TCP Connect (-sT)",
            Self::SynStealth => "SYN Stealth (-sS)",
            Self::Udp => "UDP (-sU)",
            Self::Null => "NULL (-sN)",
            Self::Fin => "FIN (-sF)",
            Self::Xmas => "Xmas (-sX)",
            Self::Ack => "ACK (-sA)",
            Self::Window => "Window (-sW)",
            Self::PingSweep => "Ping Sweep (-sn)",
            Self::SctpInit => "SCTP INIT (-sY)",
            Self::SctpCookieEcho => "SCTP COOKIE-ECHO (-sZ)",
            Self::Idle => "Idle/Zombie (-sI)",
            Self::IpProto => "IP Protocol (-sO)",
        }
    }

    pub fn from_flag(s: &str) -> Option<Self> {
        match s {
            "sT" | "connect" => Some(Self::TcpConnect),
            "sS" | "syn" => Some(Self::SynStealth),
            "sU" | "udp" => Some(Self::Udp),
            "sN" | "null" => Some(Self::Null),
            "sF" | "fin" => Some(Self::Fin),
            "sX" | "xmas" => Some(Self::Xmas),
            "sA" | "ack" => Some(Self::Ack),
            "sW" | "window" => Some(Self::Window),
            "sn" | "ping" => Some(Self::PingSweep),
            "sY" | "sctp-init" => Some(Self::SctpInit),
            "sZ" | "sctp-cookie" => Some(Self::SctpCookieEcho),
            "sI" | "idle" => Some(Self::Idle),
            "sO" | "ip-proto" => Some(Self::IpProto),
            _ => None,
        }
    }
}
