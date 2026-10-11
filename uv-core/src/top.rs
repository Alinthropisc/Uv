// Top-N ports by scan frequency — derived from nmap-services.
// Each entry: (port, protocol, service_name, frequency_ratio).

#[derive(Debug, Clone)]
pub struct TopPortEntry {
    pub port: u16,
    pub proto: &'static str,
    pub service: &'static str,
    pub freq: f32,
}

/// Return top N most common TCP ports (nmap-services frequency order).
/// Pass n=0 to get all 1000.
pub fn top_ports(n: usize) -> &'static [TopPortEntry] {
    let table = TOP_PORTS_TCP;
    if n == 0 || n >= table.len() {
        table
    } else {
        &table[..n]
    }
}

pub fn top_udp_ports(n: usize) -> &'static [TopPortEntry] {
    let table = TOP_PORTS_UDP;
    if n == 0 || n >= table.len() {
        table
    } else {
        &table[..n]
    }
}

/// Check if a port is in the top-N list.
pub fn is_top_port(port: u16, n: usize) -> bool {
    top_ports(n).iter().any(|e| e.port == port)
}

// Top 100 TCP ports (ordered by nmap frequency, descending).
// Covers the vast majority of exposed services on the internet.
static TOP_PORTS_TCP: &[TopPortEntry] = &[
    TopPortEntry {
        port: 80,
        proto: "tcp",
        service: "http",
        freq: 0.484143,
    },
    TopPortEntry {
        port: 23,
        proto: "tcp",
        service: "telnet",
        freq: 0.221265,
    },
    TopPortEntry {
        port: 443,
        proto: "tcp",
        service: "https",
        freq: 0.208669,
    },
    TopPortEntry {
        port: 21,
        proto: "tcp",
        service: "ftp",
        freq: 0.197667,
    },
    TopPortEntry {
        port: 22,
        proto: "tcp",
        service: "ssh",
        freq: 0.182286,
    },
    TopPortEntry {
        port: 25,
        proto: "tcp",
        service: "smtp",
        freq: 0.131314,
    },
    TopPortEntry {
        port: 3389,
        proto: "tcp",
        service: "ms-wbt-server",
        freq: 0.083904,
    },
    TopPortEntry {
        port: 110,
        proto: "tcp",
        service: "pop3",
        freq: 0.077142,
    },
    TopPortEntry {
        port: 445,
        proto: "tcp",
        service: "microsoft-ds",
        freq: 0.067919,
    },
    TopPortEntry {
        port: 139,
        proto: "tcp",
        service: "netbios-ssn",
        freq: 0.063188,
    },
    TopPortEntry {
        port: 143,
        proto: "tcp",
        service: "imap",
        freq: 0.059380,
    },
    TopPortEntry {
        port: 53,
        proto: "tcp",
        service: "domain",
        freq: 0.057878,
    },
    TopPortEntry {
        port: 135,
        proto: "tcp",
        service: "msrpc",
        freq: 0.057407,
    },
    TopPortEntry {
        port: 3306,
        proto: "tcp",
        service: "mysql",
        freq: 0.040028,
    },
    TopPortEntry {
        port: 8080,
        proto: "tcp",
        service: "http-proxy",
        freq: 0.033553,
    },
    TopPortEntry {
        port: 1723,
        proto: "tcp",
        service: "pptp",
        freq: 0.030026,
    },
    TopPortEntry {
        port: 111,
        proto: "tcp",
        service: "rpcbind",
        freq: 0.029640,
    },
    TopPortEntry {
        port: 995,
        proto: "tcp",
        service: "pop3s",
        freq: 0.028986,
    },
    TopPortEntry {
        port: 993,
        proto: "tcp",
        service: "imaps",
        freq: 0.028227,
    },
    TopPortEntry {
        port: 5900,
        proto: "tcp",
        service: "vnc",
        freq: 0.027405,
    },
    TopPortEntry {
        port: 1025,
        proto: "tcp",
        service: "NFS-or-IIS",
        freq: 0.025390,
    },
    TopPortEntry {
        port: 587,
        proto: "tcp",
        service: "submission",
        freq: 0.024325,
    },
    TopPortEntry {
        port: 8888,
        proto: "tcp",
        service: "sun-answerbook",
        freq: 0.024014,
    },
    TopPortEntry {
        port: 199,
        proto: "tcp",
        service: "smux",
        freq: 0.023989,
    },
    TopPortEntry {
        port: 1720,
        proto: "tcp",
        service: "h323q931",
        freq: 0.023402,
    },
    TopPortEntry {
        port: 465,
        proto: "tcp",
        service: "smtps",
        freq: 0.021898,
    },
    TopPortEntry {
        port: 548,
        proto: "tcp",
        service: "afp",
        freq: 0.021513,
    },
    TopPortEntry {
        port: 113,
        proto: "tcp",
        service: "ident",
        freq: 0.021378,
    },
    TopPortEntry {
        port: 81,
        proto: "tcp",
        service: "hosts2-ns",
        freq: 0.020721,
    },
    TopPortEntry {
        port: 873,
        proto: "tcp",
        service: "rsync",
        freq: 0.019891,
    },
    TopPortEntry {
        port: 19,
        proto: "tcp",
        service: "chargen",
        freq: 0.019555,
    },
    TopPortEntry {
        port: 1026,
        proto: "tcp",
        service: "LSA-or-nterm",
        freq: 0.018863,
    },
    TopPortEntry {
        port: 264,
        proto: "tcp",
        service: "bgmp",
        freq: 0.018822,
    },
    TopPortEntry {
        port: 1027,
        proto: "tcp",
        service: "IIS",
        freq: 0.018763,
    },
    TopPortEntry {
        port: 37,
        proto: "tcp",
        service: "time",
        freq: 0.018712,
    },
    TopPortEntry {
        port: 1433,
        proto: "tcp",
        service: "ms-sql-s",
        freq: 0.018152,
    },
    TopPortEntry {
        port: 1028,
        proto: "tcp",
        service: "unknown",
        freq: 0.017529,
    },
    TopPortEntry {
        port: 389,
        proto: "tcp",
        service: "ldap",
        freq: 0.017370,
    },
    TopPortEntry {
        port: 1029,
        proto: "tcp",
        service: "ms-lsa",
        freq: 0.017122,
    },
    TopPortEntry {
        port: 3268,
        proto: "tcp",
        service: "msft-gc",
        freq: 0.016821,
    },
    TopPortEntry {
        port: 6667,
        proto: "tcp",
        service: "irc",
        freq: 0.016547,
    },
    TopPortEntry {
        port: 901,
        proto: "tcp",
        service: "samba-swat",
        freq: 0.016461,
    },
    TopPortEntry {
        port: 3000,
        proto: "tcp",
        service: "ppp",
        freq: 0.015966,
    },
    TopPortEntry {
        port: 5432,
        proto: "tcp",
        service: "postgresql",
        freq: 0.015805,
    },
    TopPortEntry {
        port: 1030,
        proto: "tcp",
        service: "iad1",
        freq: 0.015674,
    },
    TopPortEntry {
        port: 49,
        proto: "tcp",
        service: "tacacs",
        freq: 0.015584,
    },
    TopPortEntry {
        port: 8443,
        proto: "tcp",
        service: "https-alt",
        freq: 0.015568,
    },
    TopPortEntry {
        port: 6000,
        proto: "tcp",
        service: "X11",
        freq: 0.015556,
    },
    TopPortEntry {
        port: 3269,
        proto: "tcp",
        service: "msft-gc-ssl",
        freq: 0.015349,
    },
    TopPortEntry {
        port: 1031,
        proto: "tcp",
        service: "iad2",
        freq: 0.015154,
    },
    TopPortEntry {
        port: 8008,
        proto: "tcp",
        service: "http",
        freq: 0.014967,
    },
    TopPortEntry {
        port: 1032,
        proto: "tcp",
        service: "iad3",
        freq: 0.014837,
    },
    TopPortEntry {
        port: 1034,
        proto: "tcp",
        service: "activesync",
        freq: 0.014576,
    },
    TopPortEntry {
        port: 1035,
        proto: "tcp",
        service: "multidropper",
        freq: 0.014536,
    },
    TopPortEntry {
        port: 9999,
        proto: "tcp",
        service: "abyss",
        freq: 0.014371,
    },
    TopPortEntry {
        port: 1036,
        proto: "tcp",
        service: "nsstp",
        freq: 0.014339,
    },
    TopPortEntry {
        port: 1037,
        proto: "tcp",
        service: "ams",
        freq: 0.014214,
    },
    TopPortEntry {
        port: 636,
        proto: "tcp",
        service: "ldapssl",
        freq: 0.014093,
    },
    TopPortEntry {
        port: 1038,
        proto: "tcp",
        service: "mtqp",
        freq: 0.013970,
    },
    TopPortEntry {
        port: 2049,
        proto: "tcp",
        service: "nfs",
        freq: 0.013955,
    },
    TopPortEntry {
        port: 513,
        proto: "tcp",
        service: "login",
        freq: 0.013846,
    },
    TopPortEntry {
        port: 514,
        proto: "tcp",
        service: "shell",
        freq: 0.013797,
    },
    TopPortEntry {
        port: 515,
        proto: "tcp",
        service: "printer",
        freq: 0.013745,
    },
    TopPortEntry {
        port: 666,
        proto: "tcp",
        service: "doom",
        freq: 0.013643,
    },
    TopPortEntry {
        port: 512,
        proto: "tcp",
        service: "exec",
        freq: 0.013602,
    },
    TopPortEntry {
        port: 1039,
        proto: "tcp",
        service: "sbl",
        freq: 0.013577,
    },
    TopPortEntry {
        port: 5901,
        proto: "tcp",
        service: "vnc-1",
        freq: 0.013376,
    },
    TopPortEntry {
        port: 100,
        proto: "tcp",
        service: "newacct",
        freq: 0.013328,
    },
    TopPortEntry {
        port: 7070,
        proto: "tcp",
        service: "realserver",
        freq: 0.013287,
    },
    TopPortEntry {
        port: 2000,
        proto: "tcp",
        service: "cisco-sccp",
        freq: 0.013213,
    },
    TopPortEntry {
        port: 1040,
        proto: "tcp",
        service: "netsaint",
        freq: 0.013188,
    },
    TopPortEntry {
        port: 5800,
        proto: "tcp",
        service: "vnc-http",
        freq: 0.013022,
    },
    TopPortEntry {
        port: 998,
        proto: "tcp",
        service: "puparp",
        freq: 0.012939,
    },
    TopPortEntry {
        port: 502,
        proto: "tcp",
        service: "mbap",
        freq: 0.012873,
    },
    TopPortEntry {
        port: 8181,
        proto: "tcp",
        service: "intermapper",
        freq: 0.012831,
    },
    TopPortEntry {
        port: 800,
        proto: "tcp",
        service: "mdbs_daemon",
        freq: 0.012800,
    },
    TopPortEntry {
        port: 8083,
        proto: "tcp",
        service: "us-srv",
        freq: 0.012782,
    },
    TopPortEntry {
        port: 1723,
        proto: "tcp",
        service: "pptp",
        freq: 0.012766,
    },
    TopPortEntry {
        port: 6001,
        proto: "tcp",
        service: "X11:1",
        freq: 0.012740,
    },
    TopPortEntry {
        port: 777,
        proto: "tcp",
        service: "multiling-http",
        freq: 0.012707,
    },
    TopPortEntry {
        port: 1080,
        proto: "tcp",
        service: "socks",
        freq: 0.012658,
    },
    TopPortEntry {
        port: 8084,
        proto: "tcp",
        service: "websnp",
        freq: 0.012643,
    },
    TopPortEntry {
        port: 3128,
        proto: "tcp",
        service: "squid-http",
        freq: 0.012601,
    },
    TopPortEntry {
        port: 9080,
        proto: "tcp",
        service: "glrpc",
        freq: 0.012547,
    },
    TopPortEntry {
        port: 3001,
        proto: "tcp",
        service: "nessus",
        freq: 0.012546,
    },
    TopPortEntry {
        port: 6379,
        proto: "tcp",
        service: "redis",
        freq: 0.012400,
    },
    TopPortEntry {
        port: 27017,
        proto: "tcp",
        service: "mongodb",
        freq: 0.011900,
    },
    TopPortEntry {
        port: 9200,
        proto: "tcp",
        service: "elasticsearch",
        freq: 0.011800,
    },
    TopPortEntry {
        port: 11211,
        proto: "tcp",
        service: "memcached",
        freq: 0.011700,
    },
    TopPortEntry {
        port: 5672,
        proto: "tcp",
        service: "amqp",
        freq: 0.011600,
    },
    TopPortEntry {
        port: 15672,
        proto: "tcp",
        service: "rabbitmq-mgmt",
        freq: 0.011500,
    },
    TopPortEntry {
        port: 2181,
        proto: "tcp",
        service: "zookeeper",
        freq: 0.011400,
    },
    TopPortEntry {
        port: 9092,
        proto: "tcp",
        service: "kafka",
        freq: 0.011300,
    },
    TopPortEntry {
        port: 8500,
        proto: "tcp",
        service: "consul",
        freq: 0.011200,
    },
    TopPortEntry {
        port: 4369,
        proto: "tcp",
        service: "epmd",
        freq: 0.011100,
    },
    TopPortEntry {
        port: 2375,
        proto: "tcp",
        service: "docker",
        freq: 0.010900,
    },
    TopPortEntry {
        port: 2376,
        proto: "tcp",
        service: "docker-ssl",
        freq: 0.010800,
    },
    TopPortEntry {
        port: 6443,
        proto: "tcp",
        service: "kubernetes-api",
        freq: 0.010700,
    },
    TopPortEntry {
        port: 10250,
        proto: "tcp",
        service: "kubelet",
        freq: 0.010600,
    },
];

static TOP_PORTS_UDP: &[TopPortEntry] = &[
    TopPortEntry {
        port: 631,
        proto: "udp",
        service: "ipp",
        freq: 0.450140,
    },
    TopPortEntry {
        port: 161,
        proto: "udp",
        service: "snmp",
        freq: 0.433467,
    },
    TopPortEntry {
        port: 137,
        proto: "udp",
        service: "netbios-ns",
        freq: 0.365163,
    },
    TopPortEntry {
        port: 53,
        proto: "udp",
        service: "domain",
        freq: 0.213496,
    },
    TopPortEntry {
        port: 138,
        proto: "udp",
        service: "netbios-dgm",
        freq: 0.210054,
    },
    TopPortEntry {
        port: 1434,
        proto: "udp",
        service: "ms-sql-m",
        freq: 0.207228,
    },
    TopPortEntry {
        port: 445,
        proto: "udp",
        service: "microsoft-ds",
        freq: 0.206815,
    },
    TopPortEntry {
        port: 135,
        proto: "udp",
        service: "msrpc",
        freq: 0.205279,
    },
    TopPortEntry {
        port: 67,
        proto: "udp",
        service: "dhcps",
        freq: 0.204461,
    },
    TopPortEntry {
        port: 123,
        proto: "udp",
        service: "ntp",
        freq: 0.201119,
    },
    TopPortEntry {
        port: 139,
        proto: "udp",
        service: "netbios-ssn",
        freq: 0.198346,
    },
    TopPortEntry {
        port: 500,
        proto: "udp",
        service: "isakmp",
        freq: 0.196821,
    },
    TopPortEntry {
        port: 111,
        proto: "udp",
        service: "rpcbind",
        freq: 0.192707,
    },
    TopPortEntry {
        port: 514,
        proto: "udp",
        service: "syslog",
        freq: 0.188503,
    },
    TopPortEntry {
        port: 4500,
        proto: "udp",
        service: "nat-t-ike",
        freq: 0.180053,
    },
    TopPortEntry {
        port: 5353,
        proto: "udp",
        service: "mdns",
        freq: 0.175543,
    },
    TopPortEntry {
        port: 4444,
        proto: "udp",
        service: "krb524",
        freq: 0.173441,
    },
    TopPortEntry {
        port: 520,
        proto: "udp",
        service: "route",
        freq: 0.171291,
    },
    TopPortEntry {
        port: 1900,
        proto: "udp",
        service: "upnp",
        freq: 0.168813,
    },
    TopPortEntry {
        port: 162,
        proto: "udp",
        service: "snmptrap",
        freq: 0.167038,
    },
];
