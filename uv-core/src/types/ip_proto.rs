// IP protocol number names — nmap protocols.cc style.
// Used by IP protocol scan (-sO) to label raw IP protocol numbers.

/// Returns the name for an IP protocol number.
pub fn ip_proto_name(proto: u8) -> &'static str {
    PROTO_NAMES
        .iter()
        .find(|(n, _)| *n == proto)
        .map(|(_, name)| *name)
        .unwrap_or("unknown")
}

/// Returns all (proto_num, name) pairs.
pub fn all_ip_protos() -> &'static [(u8, &'static str)] {
    PROTO_NAMES
}

/// Check if a protocol number is TCP-like (has ports).
pub fn has_ports(proto: u8) -> bool {
    matches!(proto, 6 | 17 | 132 | 33 | 136)
}

static PROTO_NAMES: &[(u8, &str)] = &[
    (0,   "hopopt"),
    (1,   "icmp"),
    (2,   "igmp"),
    (3,   "ggp"),
    (4,   "ipv4"),
    (5,   "st"),
    (6,   "tcp"),
    (7,   "cbt"),
    (8,   "egp"),
    (9,   "igp"),
    (10,  "bbn-rcc-mon"),
    (11,  "nvp-ii"),
    (12,  "pup"),
    (17,  "udp"),
    (20,  "hmp"),
    (22,  "xns-idp"),
    (27,  "rdp"),
    (29,  "iso-tp4"),
    (33,  "dccp"),
    (36,  "xtp"),
    (37,  "ddp"),
    (38,  "idpr-cmtp"),
    (41,  "ipv6"),
    (43,  "ipv6-route"),
    (44,  "ipv6-frag"),
    (45,  "idrp"),
    (46,  "rsvp"),
    (47,  "gre"),
    (50,  "esp"),
    (51,  "ah"),
    (57,  "skip"),
    (58,  "ipv6-icmp"),
    (59,  "ipv6-nonxt"),
    (60,  "ipv6-opts"),
    (70,  "visa"),
    (71,  "ipcv"),
    (73,  "cpnx"),
    (74,  "cphb"),
    (75,  "wsn"),
    (76,  "pvp"),
    (77,  "br-sat-mon"),
    (78,  "sun-nd"),
    (79,  "wb-mon"),
    (80,  "wb-expak"),
    (81,  "iso-ip"),
    (82,  "vmtp"),
    (83,  "secure-vmtp"),
    (84,  "vines"),
    (88,  "eigrp"),
    (89,  "ospf"),
    (90,  "sprite-rpc"),
    (91,  "larp"),
    (92,  "mtp"),
    (93,  "ax.25"),
    (94,  "ipip"),
    (97,  "etherip"),
    (98,  "encap"),
    (103, "pim"),
    (108, "ipcomp"),
    (112, "vrrp"),
    (113, "pgm"),
    (115, "l2tp"),
    (116, "ddx"),
    (132, "sctp"),
    (133, "fc"),
    (136, "udplite"),
    (137, "mpls-in-ip"),
    (138, "manet"),
    (139, "hip"),
    (140, "shim6"),
    (141, "wesp"),
    (142, "rohc"),
    (255, "reserved"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_protos() {
        assert_eq!(ip_proto_name(6), "tcp");
        assert_eq!(ip_proto_name(17), "udp");
        assert_eq!(ip_proto_name(89), "ospf");
        assert_eq!(ip_proto_name(47), "gre");
    }

    #[test]
    fn unknown_proto() {
        assert_eq!(ip_proto_name(200), "unknown");
    }
}
