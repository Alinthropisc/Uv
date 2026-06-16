// UDP payload templates — masscan templ-payloads.c + nmap payload.cc style.
// Each entry: port → payload bytes to send to elicit a response.
// Without a payload most UDP services silently drop empty datagrams.

/// Returns the UDP probe payload for a given port, or `None` if no probe is defined.
pub fn udp_payload(port: u16) -> Option<&'static [u8]> {
    PAYLOADS
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, payload)| *payload)
}

/// Returns all defined (port, payload) pairs.
pub fn all_payloads() -> &'static [(u16, &'static [u8])] {
    PAYLOADS
}

// DNS query for "version.bind" (CHAOS class) — triggers most DNS servers
static DNS_PROBE: &[u8] = &[
    0x00, 0x00, // transaction ID
    0x01, 0x00, // flags: standard query
    0x00, 0x01, // questions: 1
    0x00, 0x00, // answers: 0
    0x00, 0x00, // authority: 0
    0x00, 0x00, // additional: 0
    // QNAME: "version.bind"
    0x07, b'v', b'e', b'r', b's', b'i', b'o', b'n', 0x04, b'b', b'i', b'n', b'd',
    0x00, // end of QNAME
    0x00, 0x10, // QTYPE: TXT
    0x00, 0x03, // QCLASS: CHAOS
];

// NTP Mode 3 (client) request
static NTP_PROBE: &[u8] = &[
    0x1b, 0x00, 0x00, 0x00, // LI=0, VN=3, Mode=3 (client)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// SNMP v2c GetRequest for sysDescr OID (1.3.6.1.2.1.1.1.0)
static SNMP_PROBE: &[u8] = &[
    0x30, 0x29, // SEQUENCE
    0x02, 0x01, 0x01, // INTEGER version=1 (SNMPv2c)
    0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // community="public"
    0xa0, 0x1c, // GetRequest PDU
    0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // request-id
    0x02, 0x01, 0x00, // error-status=0
    0x02, 0x01, 0x00, // error-index=0
    0x30, 0x0e, // VarBindList
    0x30, 0x0c, // VarBind
    0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID 1.3.6.1.2.1.1.1.0
    0x05, 0x00, // NULL
];

// SSDP M-SEARCH for UPnP discovery
static SSDP_PROBE: &[u8] =
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";

// NetBIOS Name Service query (broadcast name lookup)
static NETBIOS_PROBE: &[u8] = &[
    0x82, 0x28, // transaction ID
    0x00, 0x00, // flags: query
    0x00, 0x01, // questions: 1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // encoded "*" (wildcard)
    0x20, b'C', b'K', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
    b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
    b'A', 0x00, 0x00, 0x21, // NBSTAT
    0x00, 0x01, // IN
];

// SIP OPTIONS probe
static SIP_PROBE: &[u8] =
    b"OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/UDP nm;branch=foo\r\nFrom: <sip:nm@nm>;tag=root\r\nTo: <sip:nm2@nm2>\r\nCall-ID: 50000\r\nCSeq: 42 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\nContact: <sip:nm@nm>\r\nAccept: application/sdp\r\n\r\n";

// CHARGEN probe (send any byte)
static CHARGEN_PROBE: &[u8] = b"\x00";

// TFTP read request for /etc/passwd (elicits error — reveals TFTP presence)
static TFTP_PROBE: &[u8] = &[
    0x00, 0x01, // opcode: RRQ
    b'/', b'e', b't', b'c', b'/', b'p', b'a', b's', b's', b'w', b'd', 0x00, b'o', b'c', b't', b'e',
    b't', 0x00,
];

// RIP v1 request
static RIP_PROBE: &[u8] = &[
    0x01, 0x01, 0x00, 0x00, // command=request, version=1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x10, // metric=16 (infinity — request full table)
];

// Memcached "stats\r\n" over UDP (with 8-byte UDP header)
static MEMCACHED_UDP_PROBE: &[u8] = &[
    0x00, 0x01, // request ID
    0x00, 0x00, // sequence
    0x00, 0x01, // num datagrams
    0x00, 0x00, // reserved
    b's', b't', b'a', b't', b's', b'\r', b'\n',
];

// QUIC version negotiation probe
static QUIC_PROBE: &[u8] = &[
    0xc0, // Long header, QUIC
    0x00, 0x00, 0x00, 0x01, // Version: 1
    0x08, // DCID length
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DCID
    0x00, // SCID length
];

static PAYLOADS: &[(u16, &[u8])] = &[
    (53,   DNS_PROBE),
    (67,   b"\x01\x01\x06\x00"),  // DHCP DISCOVER (minimal)
    (69,   TFTP_PROBE),
    (111,  b"\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), // portmapper
    (123,  NTP_PROBE),
    (137,  NETBIOS_PROBE),
    (161,  SNMP_PROBE),
    (177,  b"\x00\x01\x00\x02"),  // XDMCP QUERY
    (520,  RIP_PROBE),
    (1194, b"\x38\x01\x00\x00\x00\x00\x00\x00\x00"), // OpenVPN
    (1900, SSDP_PROBE),
    (4500, b"\x00\x00\x00\x00"),  // IKE NAT-T
    (5060, SIP_PROBE),
    (9200, b"GET / HTTP/1.0\r\n\r\n"), // Elasticsearch
    (11211, MEMCACHED_UDP_PROBE),
    (443,  QUIC_PROBE),           // QUIC/HTTP3 on 443/UDP
    (19,   CHARGEN_PROBE),
    (500,  b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00"), // IKEv1
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_payload_defined() {
        assert!(udp_payload(53).is_some());
    }

    #[test]
    fn ntp_payload_length() {
        assert_eq!(udp_payload(123).unwrap().len(), 48);
    }

    #[test]
    fn unknown_port_none() {
        assert!(udp_payload(9999).is_none());
    }
}
