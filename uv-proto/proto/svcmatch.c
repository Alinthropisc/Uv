// proto/svcmatch.c — Service name + probe lookup
// Compact table derived from nmap-service-probes (top ~60 ports).
// No file I/O, no dynamic allocation.

#include "svcmatch.h"
#include <string.h>
#include <stddef.h>

#define TCP 6
#define UDP 17

// ── Probe payloads ───────────────────────────────────────────────────────────

static const uint8_t PROBE_HTTP[]   = "GET / HTTP/1.0\r\n\r\n";
static const uint8_t PROBE_FTP[]    = "";          // passive — banner arrives first
static const uint8_t PROBE_SMTP[]   = "";          // passive
static const uint8_t PROBE_SSH[]    = "";          // passive — server sends version
static const uint8_t PROBE_DNS[]    = {            // DNS version query
    0x00,0x00,0x10,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00
};
static const uint8_t PROBE_NTP[]    = {            // NTP client request v3
    0x1b,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

#define PROBE(arr) arr, (uint16_t)sizeof(arr)
#define NO_PROBE   NULL, 0

// ── Service table ─────────────────────────────────────────────────────────────

static const uv_svc_entry_t TABLE[] = {
    { 21,    TCP, "ftp",        PROBE(PROBE_FTP)   },
    { 22,    TCP, "ssh",        PROBE(PROBE_SSH)   },
    { 23,    TCP, "telnet",     NO_PROBE           },
    { 25,    TCP, "smtp",       PROBE(PROBE_SMTP)  },
    { 53,    TCP, "dns",        PROBE(PROBE_DNS)   },
    { 53,    UDP, "dns",        PROBE(PROBE_DNS)   },
    { 80,    TCP, "http",       PROBE(PROBE_HTTP)  },
    { 110,   TCP, "pop3",       NO_PROBE           },
    { 111,   TCP, "rpcbind",    NO_PROBE           },
    { 123,   UDP, "ntp",        PROBE(PROBE_NTP)   },
    { 143,   TCP, "imap",       NO_PROBE           },
    { 194,   TCP, "irc",        NO_PROBE           },
    { 443,   TCP, "https",      PROBE(PROBE_HTTP)  },
    { 445,   TCP, "smb",        NO_PROBE           },
    { 465,   TCP, "smtps",      NO_PROBE           },
    { 587,   TCP, "submission", NO_PROBE           },
    { 993,   TCP, "imaps",      NO_PROBE           },
    { 995,   TCP, "pop3s",      NO_PROBE           },
    { 1433,  TCP, "mssql",      NO_PROBE           },
    { 1521,  TCP, "oracle",     NO_PROBE           },
    { 2375,  TCP, "docker",     PROBE(PROBE_HTTP)  },
    { 2376,  TCP, "docker-tls", PROBE(PROBE_HTTP)  },
    { 3306,  TCP, "mysql",      NO_PROBE           },
    { 3389,  TCP, "rdp",        NO_PROBE           },
    { 4444,  TCP, "metasploit", NO_PROBE           },
    { 5432,  TCP, "postgres",   NO_PROBE           },
    { 5900,  TCP, "vnc",        NO_PROBE           },
    { 6379,  TCP, "redis",      NO_PROBE           },
    { 6443,  TCP, "k8s-api",    PROBE(PROBE_HTTP)  },
    { 8080,  TCP, "http-alt",   PROBE(PROBE_HTTP)  },
    { 8443,  TCP, "https-alt",  PROBE(PROBE_HTTP)  },
    { 8888,  TCP, "http-dev",   PROBE(PROBE_HTTP)  },
    { 9200,  TCP, "elastic",    PROBE(PROBE_HTTP)  },
    { 27017, TCP, "mongodb",    NO_PROBE           },
};

#define TABLE_LEN (sizeof(TABLE) / sizeof(TABLE[0]))

// ── Banner signatures ─────────────────────────────────────────────────────────

typedef struct {
    const char *sig;     // prefix / substring to match
    uint16_t    sig_len;
    const char *service;
} uv_sig_t;

static const uv_sig_t SIGS[] = {
    { "SSH-",         4,  "ssh"       },
    { "HTTP/",        5,  "http"      },
    { "220 ",         4,  "ftp/smtp"  },
    { "220-",         4,  "ftp"       },
    { "+OK",          3,  "pop3"      },
    { "* OK",         4,  "imap"      },
    { "-ERR",         4,  "redis"     },
    { "*1\r\n",       4,  "redis"     },
    { "\xff\xfb",     2,  "telnet"    },
    { "RFB ",         4,  "vnc"       },
    { "\x4a\x00",     2,  "mysql"     },   // MySQL handshake packet len low byte
    { "AMQP",         4,  "amqp"      },
};

#define SIGS_LEN (sizeof(SIGS) / sizeof(SIGS[0]))

// ── API ───────────────────────────────────────────────────────────────────────

const char *uv_svc_name(uint16_t port, uint8_t proto)
{
    for (size_t i = 0; i < TABLE_LEN; i++)
        if (TABLE[i].port == port && TABLE[i].proto == proto)
            return TABLE[i].service;
    return "unknown";
}

const uint8_t *uv_svc_probe(uint16_t port, uint8_t proto, uint16_t *probe_len)
{
    for (size_t i = 0; i < TABLE_LEN; i++) {
        if (TABLE[i].port == port && TABLE[i].proto == proto) {
            *probe_len = TABLE[i].probe_len;
            return TABLE[i].probe;
        }
    }
    *probe_len = 0;
    return NULL;
}

const char *uv_svc_match_banner(const uint8_t *banner, uint16_t len,
                                 uint16_t port, uint8_t proto)
{
    // First try banner signatures (port-independent)
    for (size_t i = 0; i < SIGS_LEN; i++) {
        uint16_t sl = SIGS[i].sig_len;
        if (len >= sl && memcmp(banner, SIGS[i].sig, sl) == 0)
            return SIGS[i].service;
    }
    // Fall back to port-based name
    return uv_svc_name(port, proto);
}
