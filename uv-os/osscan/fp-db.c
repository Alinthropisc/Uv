/* fp-db.c — embedded OS fingerprint database
 * Entries adapted from nmap-os-db (GPL-2.0, reference)
 */
#include "fp-db.h"

static const uv_fp_db_entry_t UV_FP_DB[] = {
    /* name                      os_class   cpe                               ttl  opts     ws   df     ecn    icmp_df */
    { "Linux 6.x",              "Linux",   "cpe:/o:linux:linux_kernel:6",     64, "MSTNW",  7, true,  true,  false },
    { "Linux 5.x",              "Linux",   "cpe:/o:linux:linux_kernel:5",     64, "MSTNW",  7, true,  true,  false },
    { "Linux 4.x",              "Linux",   "cpe:/o:linux:linux_kernel:4",     64, "MSTNW",  7, true,  false, false },
    { "Linux 3.x",              "Linux",   "cpe:/o:linux:linux_kernel:3",     64, "MSTNW",  6, true,  false, false },
    { "Linux 2.6.x",            "Linux",   "cpe:/o:linux:linux_kernel:2.6",   64, "MSTNW",  6, true,  false, false },
    { "Windows 11",             "Windows", "cpe:/o:microsoft:windows_11",    128, "MSNWT",  8, true,  true,  true  },
    { "Windows 10 1903+",       "Windows", "cpe:/o:microsoft:windows_10",    128, "MSNWT",  8, true,  true,  true  },
    { "Windows 10",             "Windows", "cpe:/o:microsoft:windows_10",    128, "MSNWT",  8, true,  false, true  },
    { "Windows Server 2022",    "Windows", "cpe:/o:microsoft:windows_server_2022", 128, "MSNWT", 8, true, true, true },
    { "Windows Server 2019",    "Windows", "cpe:/o:microsoft:windows_server_2019", 128, "MSNWT", 8, true, true, true },
    { "Windows Server 2016",    "Windows", "cpe:/o:microsoft:windows_server_2016", 128, "MSNWT", 8, true, false, true },
    { "Windows 8.1",            "Windows", "cpe:/o:microsoft:windows_8.1",   128, "MSNWT",  8, true,  false, true  },
    { "Windows 7",              "Windows", "cpe:/o:microsoft:windows_7",     128, "MSNWT",  8, false, false, false },
    { "Windows XP SP3",         "Windows", "cpe:/o:microsoft:windows_xp",    128, "MSNWT", 255, false, false, false },
    { "macOS 14 Sonoma",        "macOS",   "cpe:/o:apple:macos:14",           64, "MSTWE",  6, true,  true,  true  },
    { "macOS 13 Ventura",       "macOS",   "cpe:/o:apple:macos:13",           64, "MSTWE",  6, true,  true,  true  },
    { "macOS 12 Monterey",      "macOS",   "cpe:/o:apple:macos:12",           64, "MSTWE",  6, true,  true,  true  },
    { "macOS 11 Big Sur",       "macOS",   "cpe:/o:apple:macos:11",           64, "MSTWE",  6, true,  false, true  },
    { "FreeBSD 14",             "BSD",     "cpe:/o:freebsd:freebsd:14",       64, "MSTNW",  6, true,  false, false },
    { "FreeBSD 13",             "BSD",     "cpe:/o:freebsd:freebsd:13",       64, "MSTNW",  6, true,  false, false },
    { "OpenBSD 7.x",            "BSD",     "cpe:/o:openbsd:openbsd:7",       255, "MSTN",  255, true, false, true  },
    { "NetBSD 9.x",             "BSD",     "cpe:/o:netbsd:netbsd:9",          64, "MSTNW",  6, true,  false, false },
    { "Cisco IOS 15.x",         "IOS",     "cpe:/o:cisco:ios:15",            255, "MSN",   255, false, false, false },
    { "Cisco IOS 12.x",         "IOS",     "cpe:/o:cisco:ios:12",            255, "MSN",   255, false, false, false },
    { "Cisco IOS XE 17.x",      "IOS-XE",  "cpe:/o:cisco:ios_xe:17",        255, "MSNW",  255, true,  false, false },
    { "Android 14",             "Android", "cpe:/o:google:android:14",        64, "MSTNW",  7, true,  true,  false },
    { "Android 13",             "Android", "cpe:/o:google:android:13",        64, "MSTNW",  7, true,  true,  false },
    { "Android 12",             "Android", "cpe:/o:google:android:12",        64, "MSTNW",  7, true,  true,  false },
    { "VMware ESXi 8.x",        "VMware",  "cpe:/o:vmware:esxi:8",            64, "MSTNW",  7, true,  false, false },
    { "VMware ESXi 7.x",        "VMware",  "cpe:/o:vmware:esxi:7",            64, "MSTNW",  7, true,  false, false },
    { "Juniper JunOS 21",       "JunOS",   "cpe:/o:juniper:junos:21",         64, "MSTNW",  6, true,  false, true  },
    { "pfSense 2.6 (FreeBSD)",  "BSD",     "cpe:/o:pfsense:pfsense:2.6",      64, "MSTNW",  6, true,  false, false },
};

static const int UV_FP_DB_COUNT =
    (int)(sizeof(UV_FP_DB) / sizeof(UV_FP_DB[0]));

const uv_fp_db_entry_t *uv_fp_db_get(int *count) {
    if (count) *count = UV_FP_DB_COUNT;
    return UV_FP_DB;
}
