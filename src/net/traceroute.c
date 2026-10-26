#include "wincompat.h"
#include "traceroute.h"
#include "exec/exec.h"
#include "util.h"
#include "error.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Find the last dotted-quad token on a line. */
static void parse_hop_line(char *line, uint32_t *ip) {
    *ip = 0;
    char *p = line;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r') p++;
        if (!*p) break;
        char *start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\r') p++;
        char saved = *p;
        *p = 0;
        uint32_t maybe = ip_from_string(start);
        if (maybe) *ip = maybe;
        *p = saved;
        if (!*p) break;
    }
}

int traceroute_run(const char *target, int max_hops, int timeout_ms, TraceResult *out) {
    memset(out, 0, sizeof(*out));
    if (!target || !*target) return E_ARG;
    if (max_hops <= 0) max_hops = 8;
    if (timeout_ms <= 0) timeout_ms = 400;

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "tracert.exe -d -h %d -w %d %s", max_hops, timeout_ms, target);

    char buf[16384];
    int to = max_hops * timeout_ms * 3 + 8000;
    if (exec_capture_cmd(cmd, buf, sizeof(buf), to) != E_OK) {
        LOGW("tracert 执行失败");
        return E_IO;
    }

    int line_index = 0;
    char line[256];
    int li = 0;
    for (char *q = buf; *q; q++) {
        if (*q == '\n' || (*q == '\r' && q[1] == '\n')) {
            line[li] = 0;
            if (line_index > 0 && li > 0) {
                uint32_t ip = 0;
                parse_hop_line(line, &ip);
                if (ip && out->count < TR_MAX_HOPS) {
                    out->hops[out->count].ip = ip;
                    out->hops[out->count].hop = out->count + 1;
                    out->count++;
                }
            }
            line_index++;
            li = 0;
            if (*q == '\r') q++;
        } else if (li < 255) {
            line[li++] = *q;
        }
    }
    return E_OK;
}
