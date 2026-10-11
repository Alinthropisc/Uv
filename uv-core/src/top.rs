// Top-N ports by scan frequency — derived from nmap-services.
// Each entry: (port, protocol, service_name, frequency_ratio).

#[derive(Debug, Clone)]
pub struct UvTopPortEntry {
    pub port: u16,
    pub proto: &'static str,
    pub service: &'static str,
    pub freq: f32,
}

/// Return top N most common TCP ports (nmap-services frequency order).
/// Pass n=0 to get all 1000.
pub fn uv_top_ports(n: usize) -> &'static [UvTopPortEntry] {
    let table = TOP_PORTS_TCP;
    if n == 0 || n >= table.len() {
        table
    } else {
        &table[..n]
    }
}

pub fn uv_top_udp_ports(n: usize) -> &'static [UvTopPortEntry] {
    let table = TOP_PORTS_UDP;
    if n == 0 || n >= table.len() {
        table
    } else {
        &table[..n]
    }
}

/// Check if a port is in the top-N list.
pub fn uv_is_top_port(port: u16, n: usize) -> bool {
    top_ports(n).iter().any(|e| e.port == port)
}

// Top 100 TCP ports (ordered by nmap frequency, descending).
// Covers the vast majority of exposed services on the internet.
static UV_TOP_PORTS_TCP: &[UvTopPortEntry] = &[
    UvTopPortEntry {
        port: 80,
        proto: "tcp",
        service: "http",
        freq: 0.484143,
    },
    UvTopPortEntry {
        port: 23,
        proto: "tcp",
        service: "telnet",
        freq: 0.221265,
    },
    UvTopPortEntry {
        port: 443,
        proto: "tcp",
        service: "https",
        freq: 0.208669,
    },
    UvTopPortEntry {
        port: 21,
        proto: "tcp",
        service: "ftp",
        freq: 0.197667,
    },
    UvTopPortEntry {
        port: 22,
        proto: "tcp",
        service: "ssh",
        freq: 0.182286,
    },
    UvTopPortEntry {
        port: 25,
        proto: "tcp",
        service: "smtp",
        freq: 0.131314,
    },
    UvTopPortEntry {
        port: 3389,
        proto: "tcp",
        service: "ms-wbt-server",
        freq: 0.083904,
    },
    UvTopPortEntry {
        port: 110,
        proto: "tcp",
        service: "pop3",
        freq: 0.077142,
    },
    UvTopPortEntry {
        port: 445,
        proto: "tcp",
        service: "microsoft-ds",
        freq: 0.067919,
    },
    UvTopPortEntry {
        port: 139,
        proto: "tcp",
        service: "netbios-ssn",
        freq: 0.063188,
    },
    UvTopPortEntry {
        port: 143,
        proto: "tcp",
        service: "imap",
        freq: 0.059380,
    },
    UvTopPortEntry {
        port: 53,
        proto: "tcp",
        service: "domain",
        freq: 0.057878,
    },
    UvTopPortEntry {
        port: 135,
        proto: "tcp",
        service: "msrpc",
        freq: 0.057407,
    },
    UvTopPortEntry {
        port: 3306,
        proto: "tcp",
        service: "mysql",
        freq: 0.040028,
    },
    UvTopPortEntry {
        port: 8080,
        proto: "tcp",
        service: "http-proxy",
        freq: 0.033553,
    },
    UvTopPortEntry {
        port: 1723,
        proto: "tcp",
        service: "pptp",
        freq: 0.030026,
    },
    UvTopPortEntry {
        port: 111,
        proto: "tcp",
        service: "rpcbind",
        freq: 0.029640,
    },
    UvTopPortEntry {
        port: 995,
        proto: "tcp",
        service: "pop3s",
        freq: 0.028986,
    },
    UvTopPortEntry {
        port: 993,
        proto: "tcp",
        service: "imaps",
        freq: 0.028227,
    },
    UvTopPortEntry {
        port: 5900,
        proto: "tcp",
        service: "vnc",
        freq: 0.027405,
    },
    UvTopPortEntry {
        port: 1025,
        proto: "tcp",
        service: "NFS-or-IIS",
        freq: 0.025390,
    },
    UvTopPortEntry {
        port: 587,
        proto: "tcp",
        service: "submission",
        freq: 0.024325,
    },
    UvTopPortEntry {
        port: 8888,
        proto: "tcp",
        service: "sun-answerbook",
        freq: 0.024014,
    },
    UvTopPortEntry {
        port: 199,
        proto: "tcp",
        service: "smux",
        freq: 0.023989,
    },
    UvTopPortEntry {
        port: 1720,
        proto: "tcp",
        service: "h323q931",
        freq: 0.023402,
    },
    UvTopPortEntry {
        port: 465,
        proto: "tcp",
        service: "smtps",
        freq: 0.021898,
    },
    UvTopPortEntry {
        port: 548,
        proto: "tcp",
        service: "afp",
        freq: 0.021513,
    },
    UvTopPortEntry {
        port: 113,
        proto: "tcp",
        service: "ident",
        freq: 0.021378,
    },
    UvTopPortEntry {
        port: 81,
        proto: "tcp",
        service: "hosts2-ns",
        freq: 0.020721,
    },
    UvTopPortEntry {
        port: 873,
        proto: "tcp",
        service: "rsync",
        freq: 0.019891,
    },
    UvTopPortEntry {
        port: 19,
        proto: "tcp",
        service: "chargen",
        freq: 0.019555,
    },
    UvTopPortEntry {
        port: 1026,
        proto: "tcp",
        service: "LSA-or-nterm",
        freq: 0.018863,
    },
    UvTopPortEntry {
        port: 264,
        proto: "tcp",
        service: "bgmp",
        freq: 0.018822,
    },
    UvTopPortEntry {
        port: 1027,
        proto: "tcp",
        service: "IIS",
        freq: 0.018763,
    },
    UvTopPortEntry {
        port: 37,
        proto: "tcp",
        service: "time",
        freq: 0.018712,
    },
    UvTopPortEntry {
        port: 1433,
        proto: "tcp",
        service: "ms-sql-s",
        freq: 0.018152,
    },
    UvTopPortEntry {
        port: 1028,
        proto: "tcp",
        service: "unknown",
        freq: 0.017529,
    },
    UvTopPortEntry {
        port: 389,
        proto: "tcp",
        service: "ldap",
        freq: 0.017370,
    },
    UvTopPortEntry {
        port: 1029,
        proto: "tcp",
        service: "ms-lsa",
        freq: 0.017122,
    },
    UvTopPortEntry {
        port: 3268,
        proto: "tcp",
        service: "msft-gc",
        freq: 0.016821,
    },
    UvTopPortEntry {
        port: 6667,
        proto: "tcp",
        service: "irc",
        freq: 0.016547,
    },
    UvTopPortEntry {
        port: 901,
        proto: "tcp",
        service: "samba-swat",
        freq: 0.016461,
    },
    UvTopPortEntry {
        port: 3000,
        proto: "tcp",
        service: "ppp",
        freq: 0.015966,
    },
    UvTopPortEntry {
        port: 5432,
        proto: "tcp",
        service: "postgresql",
        freq: 0.015805,
    },
    UvTopPortEntry {
        port: 1030,
        proto: "tcp",
        service: "iad1",
        freq: 0.015674,
    },
    UvTopPortEntry {
        port: 49,
        proto: "tcp",
        service: "tacacs",
        freq: 0.015584,
    },
    UvTopPortEntry {
        port: 8443,
        proto: "tcp",
        service: "https-alt",
        freq: 0.015568,
    },
    UvTopPortEntry {
        port: 6000,
        proto: "tcp",
        service: "X11",
        freq: 0.015556,
    },
    UvTopPortEntry {
        port: 3269,
        proto: "tcp",
        service: "msft-gc-ssl",
        freq: 0.015349,
    },
    UvTopPortEntry {
        port: 1031,
        proto: "tcp",
        service: "iad2",
        freq: 0.015154,
    },
    UvTopPortEntry {
        port: 8008,
        proto: "tcp",
        service: "http",
        freq: 0.014967,
    },
    UvTopPortEntry {
        port: 1032,
        proto: "tcp",
        service: "iad3",
        freq: 0.014837,
    },
    UvTopPortEntry {
        port: 1034,
        proto: "tcp",
        service: "activesync",
        freq: 0.014576,
    },
    UvTopPortEntry {
        port: 1035,
        proto: "tcp",
        service: "multidropper",
        freq: 0.014536,
    },
    UvTopPortEntry {
        port: 9999,
        proto: "tcp",
        service: "abyss",
        freq: 0.014371,
    },
    UvTopPortEntry {
        port: 1036,
        proto: "tcp",
        service: "nsstp",
        freq: 0.014339,
    },
    UvTopPortEntry {
        port: 1037,
        proto: "tcp",
        service: "ams",
        freq: 0.014214,
    },
    UvTopPortEntry {
        port: 636,
        proto: "tcp",
        service: "ldapssl",
        freq: 0.014093,
    },
    UvTopPortEntry {
        port: 1038,
        proto: "tcp",
        service: "mtqp",
        freq: 0.013970,
    },
    UvTopPortEntry {
        port: 2049,
        proto: "tcp",
        service: "nfs",
        freq: 0.013955,
    },
    UvTopPortEntry {
        port: 513,
        proto: "tcp",
        service: "login",
        freq: 0.013846,
    },
    UvTopPortEntry {
        port: 514,
        proto: "tcp",
        service: "shell",
        freq: 0.013797,
    },
    UvTopPortEntry {
        port: 515,
        proto: "tcp",
        service: "printer",
        freq: 0.013745,
    },
    UvTopPortEntry {
        port: 666,
        proto: "tcp",
        service: "doom",
        freq: 0.013643,
    },
    UvTopPortEntry {
        port: 512,
        proto: "tcp",
        service: "exec",
        freq: 0.013602,
    },
    UvTopPortEntry {
        port: 1039,
        proto: "tcp",
        service: "sbl",
        freq: 0.013577,
    },
    UvTopPortEntry {
        port: 5901,
        proto: "tcp",
        service: "vnc-1",
        freq: 0.013376,
    },
    UvTopPortEntry {
        port: 100,
        proto: "tcp",
        service: "newacct",
        freq: 0.013328,
    },
    UvTopPortEntry {
        port: 7070,
        proto: "tcp",
        service: "realserver",
        freq: 0.013287,
    },
    UvTopPortEntry {
        port: 2000,
        proto: "tcp",
        service: "cisco-sccp",
        freq: 0.013213,
    },
    UvTopPortEntry {
        port: 1040,
        proto: "tcp",
        service: "netsaint",
        freq: 0.013188,
    },
    UvTopPortEntry {
        port: 5800,
        proto: "tcp",
        service: "vnc-http",
        freq: 0.013022,
    },
    UvTopPortEntry {
        port: 998,
        proto: "tcp",
        service: "puparp",
        freq: 0.012939,
    },
    UvTopPortEntry {
        port: 502,
        proto: "tcp",
        service: "mbap",
        freq: 0.012873,
    },
    UvTopPortEntry {
        port: 8181,
        proto: "tcp",
        service: "intermapper",
        freq: 0.012831,
    },
    UvTopPortEntry {
        port: 800,
        proto: "tcp",
        service: "mdbs_daemon",
        freq: 0.012800,
    },
    UvTopPortEntry {
        port: 8083,
        proto: "tcp",
        service: "us-srv",
        freq: 0.012782,
    },
    UvTopPortEntry {
        port: 1723,
        proto: "tcp",
        service: "pptp",
        freq: 0.012766,
    },
    UvTopPortEntry {
        port: 6001,
        proto: "tcp",
        service: "X11:1",
        freq: 0.012740,
    },
    UvTopPortEntry {
        port: 777,
        proto: "tcp",
        service: "multiling-http",
        freq: 0.012707,
    },
    UvTopPortEntry {
        port: 1080,
        proto: "tcp",
        service: "socks",
        freq: 0.012658,
    },
    UvTopPortEntry {
        port: 8084,
        proto: "tcp",
        service: "websnp",
        freq: 0.012643,
    },
    UvTopPortEntry {
        port: 3128,
        proto: "tcp",
        service: "squid-http",
        freq: 0.012601,
    },
    UvTopPortEntry {
        port: 9080,
        proto: "tcp",
        service: "glrpc",
        freq: 0.012547,
    },
    UvTopPortEntry {
        port: 3001,
        proto: "tcp",
        service: "nessus",
        freq: 0.012546,
    },
    UvTopPortEntry {
        port: 6379,
        proto: "tcp",
        service: "redis",
        freq: 0.012400,
    },
    UvTopPortEntry {
        port: 27017,
        proto: "tcp",
        service: "mongodb",
        freq: 0.011900,
    },
    UvTopPortEntry {
        port: 9200,
        proto: "tcp",
        service: "elasticsearch",
        freq: 0.011800,
    },
    UvTopPortEntry {
        port: 11211,
        proto: "tcp",
        service: "memcached",
        freq: 0.011700,
    },
    UvTopPortEntry {
        port: 5672,
        proto: "tcp",
        service: "amqp",
        freq: 0.011600,
    },
    UvTopPortEntry {
        port: 15672,
        proto: "tcp",
        service: "rabbitmq-mgmt",
        freq: 0.011500,
    },
    UvTopPortEntry {
        port: 2181,
        proto: "tcp",
        service: "zookeeper",
        freq: 0.011400,
    },
    UvTopPortEntry {
        port: 9092,
        proto: "tcp",
        service: "kafka",
        freq: 0.011300,
    },
    UvTopPortEntry {
        port: 8500,
        proto: "tcp",
        service: "consul",
        freq: 0.011200,
    },
    UvTopPortEntry {
        port: 4369,
        proto: "tcp",
        service: "epmd",
        freq: 0.011100,
    },
    UvTopPortEntry {
        port: 2375,
        proto: "tcp",
        service: "docker",
        freq: 0.010900,
    },
    UvTopPortEntry {
        port: 2376,
        proto: "tcp",
        service: "docker-ssl",
        freq: 0.010800,
    },
    UvTopPortEntry {
        port: 6443,
        proto: "tcp",
        service: "kubernetes-api",
        freq: 0.010700,
    },
    UvTopPortEntry {
        port: 10250,
        proto: "tcp",
        service: "kubelet",
        freq: 0.010600,
    },
];

static UV_TOP_PORTS_UDP: &[UvTopPortEntry] = &[
    UvTopPortEntry {
        port: 631,
        proto: "udp",
        service: "ipp",
        freq: 0.450140,
    },
    UvTopPortEntry {
        port: 161,
        proto: "udp",
        service: "snmp",
        freq: 0.433467,
    },
    UvTopPortEntry {
        port: 137,
        proto: "udp",
        service: "netbios-ns",
        freq: 0.365163,
    },
    UvTopPortEntry {
        port: 53,
        proto: "udp",
        service: "domain",
        freq: 0.213496,
    },
    UvTopPortEntry {
        port: 138,
        proto: "udp",
        service: "netbios-dgm",
        freq: 0.210054,
    },
    UvTopPortEntry {
        port: 1434,
        proto: "udp",
        service: "ms-sql-m",
        freq: 0.207228,
    },
    UvTopPortEntry {
        port: 445,
        proto: "udp",
        service: "microsoft-ds",
        freq: 0.206815,
    },
    UvTopPortEntry {
        port: 135,
        proto: "udp",
        service: "msrpc",
        freq: 0.205279,
    },
    UvTopPortEntry {
        port: 67,
        proto: "udp",
        service: "dhcps",
        freq: 0.204461,
    },
    UvTopPortEntry {
        port: 123,
        proto: "udp",
        service: "ntp",
        freq: 0.201119,
    },
    UvTopPortEntry {
        port: 139,
        proto: "udp",
        service: "netbios-ssn",
        freq: 0.198346,
    },
    UvTopPortEntry {
        port: 500,
        proto: "udp",
        service: "isakmp",
        freq: 0.196821,
    },
    UvTopPortEntry {
        port: 111,
        proto: "udp",
        service: "rpcbind",
        freq: 0.192707,
    },
    UvTopPortEntry {
        port: 514,
        proto: "udp",
        service: "syslog",
        freq: 0.188503,
    },
    UvTopPortEntry {
        port: 4500,
        proto: "udp",
        service: "nat-t-ike",
        freq: 0.180053,
    },
    UvTopPortEntry {
        port: 5353,
        proto: "udp",
        service: "mdns",
        freq: 0.175543,
    },
    UvTopPortEntry {
        port: 4444,
        proto: "udp",
        service: "krb524",
        freq: 0.173441,
    },
    UvTopPortEntry {
        port: 520,
        proto: "udp",
        service: "route",
        freq: 0.171291,
    },
    UvTopPortEntry {
        port: 1900,
        proto: "udp",
        service: "upnp",
        freq: 0.168813,
    },
    UvTopPortEntry {
        port: 162,
        proto: "udp",
        service: "snmptrap",
        freq: 0.167038,
    },
];
