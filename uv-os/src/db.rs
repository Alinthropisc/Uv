// Embedded OS signature database — Repository pattern.
// A minimal subset of nmap-os-db entries as static Rust data.

#[derive(Debug, Clone)]
pub struct OsEntry {
    pub name: String,
    pub os_class: String,
    pub cpe: String,
    pub ttl: u8,
    pub window_scale: Option<u8>,
    pub df: bool,
    pub ecn: bool,
    pub tcp_opt_str: String,
    pub icmp_echo_df: bool,
}

pub struct OsDb {
    entries: Vec<OsEntry>,
}

impl OsDb {
    /// Load the embedded signature set.
    pub fn built_in() -> Self {
        Self {
            entries: built_in_entries(),
        }
    }

    pub fn entries(&self) -> &[OsEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[allow(clippy::too_many_arguments)]
fn e(
    name: &str,
    os_class: &str,
    cpe: &str,
    ttl: u8,
    ws: Option<u8>,
    df: bool,
    ecn: bool,
    opts: &str,
    idf: bool,
) -> OsEntry {
    OsEntry {
        name: name.into(),
        os_class: os_class.into(),
        cpe: cpe.into(),
        ttl,
        window_scale: ws,
        df,
        ecn,
        tcp_opt_str: opts.into(),
        icmp_echo_df: idf,
    }
}

fn built_in_entries() -> Vec<OsEntry> {
    vec![
        e(
            "Linux 5.x",
            "Linux",
            "cpe:/o:linux:linux_kernel:5",
            64,
            Some(7),
            true,
            true,
            "MSTNW",
            false,
        ),
        e(
            "Linux 4.x",
            "Linux",
            "cpe:/o:linux:linux_kernel:4",
            64,
            Some(7),
            true,
            false,
            "MSTNW",
            false,
        ),
        e(
            "Linux 3.x",
            "Linux",
            "cpe:/o:linux:linux_kernel:3",
            64,
            Some(7),
            true,
            false,
            "MSTNW",
            false,
        ),
        e(
            "Windows 11",
            "Windows",
            "cpe:/o:microsoft:windows_11",
            128,
            Some(8),
            true,
            true,
            "MSNWT",
            true,
        ),
        e(
            "Windows 10",
            "Windows",
            "cpe:/o:microsoft:windows_10",
            128,
            Some(8),
            true,
            true,
            "MSNWT",
            true,
        ),
        e(
            "Windows Server 2022",
            "Windows",
            "cpe:/o:microsoft:windows_server_2022",
            128,
            Some(8),
            true,
            true,
            "MSNWT",
            true,
        ),
        e(
            "Windows 7",
            "Windows",
            "cpe:/o:microsoft:windows_7",
            128,
            Some(8),
            false,
            false,
            "MSNWT",
            false,
        ),
        e(
            "macOS 13 Ventura",
            "macOS",
            "cpe:/o:apple:macos:13",
            64,
            Some(6),
            true,
            true,
            "MSTWE",
            true,
        ),
        e(
            "macOS 12 Monterey",
            "macOS",
            "cpe:/o:apple:macos:12",
            64,
            Some(6),
            true,
            true,
            "MSTWE",
            true,
        ),
        e(
            "FreeBSD 13",
            "BSD",
            "cpe:/o:freebsd:freebsd:13",
            64,
            Some(6),
            true,
            false,
            "MSTNW",
            false,
        ),
        e(
            "OpenBSD 7",
            "BSD",
            "cpe:/o:openbsd:openbsd:7",
            255,
            None,
            true,
            false,
            "MSTN",
            true,
        ),
        e(
            "Cisco IOS 15",
            "IOS",
            "cpe:/o:cisco:ios:15",
            255,
            None,
            false,
            false,
            "MSN",
            false,
        ),
        e(
            "Android 12+",
            "Android",
            "cpe:/o:google:android:12",
            64,
            Some(7),
            true,
            true,
            "MSTNW",
            false,
        ),
        e(
            "ESXi 7",
            "VMware",
            "cpe:/o:vmware:esxi:7",
            64,
            Some(7),
            true,
            false,
            "MSTNW",
            false,
        ),
    ]
}
