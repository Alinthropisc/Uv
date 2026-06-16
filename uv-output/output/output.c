/* output.c — output handle lifecycle + format dispatch
 * Derived from masscan/src/output.c (MIT License)
 */
#include "output.h"
#include <stdlib.h>
#include <string.h>

struct uv_output {
    uv_output_fmt_t fmt;
    FILE           *fp;
    bool            header_written;
    uint64_t        count;
};

uv_output_t *uv_output_open(uv_output_fmt_t fmt, const char *path) {
    uv_output_t *out = calloc(1, sizeof(*out));
    if (!out) return NULL;
    out->fmt = fmt;
    out->fp  = path ? fopen(path, "wb") : stdout;
    if (!out->fp) { free(out); return NULL; }
    return out;
}

static void write_header(uv_output_t *out) {
    if (out->header_written) return;
    out->header_written = true;
    switch (out->fmt) {
    case UV_OUT_XML:
        fprintf(out->fp,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<uvscan>\n");
        break;
    case UV_OUT_JSON:
        fprintf(out->fp, "[\n");
        break;
    default:
        break;
    }
}

void uv_output_write(uv_output_t *out, const uv_port_record_t *rec) {
    if (!out || !rec) return;
    write_header(out);

    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
        (rec->ip >> 24) & 0xFF,
        (rec->ip >> 16) & 0xFF,
        (rec->ip >>  8) & 0xFF,
         rec->ip        & 0xFF);

    const char *proto_str = (rec->proto == 6)  ? "tcp"
                          : (rec->proto == 17) ? "udp"
                          : "unknown";
    const char *svc   = rec->service ? rec->service : "unknown";
    const char *state = (rec->state == UV_PORT_OPEN)     ? "open"
                      : (rec->state == UV_PORT_CLOSED)   ? "closed"
                      : "filtered";

    switch (out->fmt) {
    case UV_OUT_PLAIN:
        fprintf(out->fp, "%-16s %5u/%s  %s  %s\n",
                ip_str, rec->port, proto_str, state, svc);
        break;

    case UV_OUT_GREPPABLE:
        /* nmap -oG: Host: ip ()  Ports: port/state/proto/owner/service/version/extrainfo/ */
        fprintf(out->fp, "Host: %s ()\tPorts: %u/%s/%s///%s//\n",
                ip_str, rec->port, state, proto_str, svc);
        break;

    case UV_OUT_JSON:
        if (out->count > 0) fprintf(out->fp, ",\n");
        fprintf(out->fp,
            "  {\"ip\":\"%s\",\"port\":%u,\"proto\":\"%s\","
            "\"state\":\"%s\",\"service\":\"%s\",\"banner\":\"%s\","
            "\"rtt_us\":%u}",
            ip_str, rec->port, proto_str, state, svc,
            rec->banner ? rec->banner : "", rec->rtt_us);
        break;

    case UV_OUT_XML:
        fprintf(out->fp,
            "  <host ip=\"%s\">"
            "<port number=\"%u\" protocol=\"%s\" state=\"%s\""
            " service=\"%s\" banner=\"%s\" rtt_us=\"%u\"/>"
            "</host>\n",
            ip_str, rec->port, proto_str, state, svc,
            rec->banner ? rec->banner : "", rec->rtt_us);
        break;

    case UV_OUT_LIST:
        fprintf(out->fp, "%s:%u\n", ip_str, rec->port);
        break;

    case UV_OUT_BINARY:
        /* masscan binary record: 4B ip + 2B port + 1B proto + 1B state */
        fwrite(&rec->ip,    4, 1, out->fp);
        fwrite(&rec->port,  2, 1, out->fp);
        fwrite(&rec->proto, 1, 1, out->fp);
        { uint8_t s = (uint8_t)rec->state; fwrite(&s, 1, 1, out->fp); }
        break;
    }
    out->count++;
}

void uv_output_close(uv_output_t *out) {
    if (!out) return;
    switch (out->fmt) {
    case UV_OUT_XML:
        if (out->header_written) fprintf(out->fp, "</uvscan>\n");
        break;
    case UV_OUT_JSON:
        if (out->header_written) fprintf(out->fp, "\n]\n");
        break;
    default:
        break;
    }
    if (out->fp && out->fp != stdout) fclose(out->fp);
    free(out);
}

const char *uv_output_fmt_name(uv_output_fmt_t fmt) {
    switch (fmt) {
    case UV_OUT_PLAIN:     return "plain";
    case UV_OUT_GREPPABLE: return "greppable";
    case UV_OUT_JSON:      return "json";
    case UV_OUT_XML:       return "xml";
    case UV_OUT_BINARY:    return "binary";
    case UV_OUT_LIST:      return "list";
    }
    return "unknown";
}

uv_output_fmt_t uv_output_fmt_parse(const char *s) {
    if (!s) return UV_OUT_PLAIN;
    if (strcmp(s, "oG") == 0 || strcmp(s, "greppable") == 0) return UV_OUT_GREPPABLE;
    if (strcmp(s, "oJ") == 0 || strcmp(s, "json")      == 0) return UV_OUT_JSON;
    if (strcmp(s, "oX") == 0 || strcmp(s, "xml")       == 0) return UV_OUT_XML;
    if (strcmp(s, "oB") == 0 || strcmp(s, "binary")    == 0) return UV_OUT_BINARY;
    if (strcmp(s, "oL") == 0 || strcmp(s, "list")      == 0) return UV_OUT_LIST;
    return UV_OUT_PLAIN;
}
