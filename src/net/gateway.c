#include "wincompat.h"
#include "gateway.h"
#include "util.h"
#include "error.h"
#include "log.h"
#include <winhttp.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Common default gateway addresses of home routers / ONT (光猫). */
static const char *CANDIDATES[] = {
    "192.168.1.1","192.168.2.1","192.168.3.1","192.168.4.1","192.168.8.1",
    "192.168.10.1","192.168.11.1","192.168.16.1","192.168.20.1","192.168.31.1",
    "192.168.100.1","192.168.101.1","192.168.123.1","192.168.199.1",
    "10.0.0.1","10.0.1.1","10.10.0.1","10.10.1.1","10.1.1.1",
    "172.16.0.1","172.16.1.1","172.17.0.1","172.19.0.1","172.20.0.1","172.30.0.1"
};

static int ascii_lower(int c) { return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c; }

static int est_distance(int ttl) {
    int base = 64;
    if (ttl > 128) base = 255;
    else if (ttl > 64) base = 128;
    else if (ttl > 32) base = 64;
    else base = 32;
    int d = base - ttl;
    return d < 1 ? 1 : d;
}

#define GW_THREADS 16

typedef struct {
    uint32_t self_ip, local_gw;
    int timeout_ms;
    int start, step;
    GwHop *out;
    volatile LONG *count;
    LONG cap;
} GwWorker;

static DWORD WINAPI gw_thread(LPVOID p) {
    GwWorker *w = (GwWorker *)p;
    HANDLE icmp = IcmpCreateFile();
    if (icmp == INVALID_HANDLE_VALUE) return 0;
    int nc = (int)(sizeof(CANDIDATES) / sizeof(CANDIDATES[0]));
    for (int i = w->start; i < nc; i += w->step) {
        uint32_t ip = ip_from_string(CANDIDATES[i]);
        if (!ip || ip == w->self_ip || ip == w->local_gw) continue;
        BYTE reply[sizeof(ICMP_ECHO_REPLY) + 32];
        DWORD rc = IcmpSendEcho(icmp, (IPAddr)ip, NULL, 0, NULL, reply, sizeof(reply), (DWORD)w->timeout_ms);
        if (rc > 0 && ((ICMP_ECHO_REPLY *)reply)->Status == IP_SUCCESS) {
            LONG idx = InterlockedIncrement(w->count) - 1;
            if (idx < w->cap) {
                w->out[idx].ip = ip;
                w->out[idx].distance = est_distance(((ICMP_ECHO_REPLY *)reply)->Options.Ttl);
            }
        }
    }
    IcmpCloseHandle(icmp);
    return 0;
}

int gateway_scan(uint32_t self_ip, uint32_t local_gw, int timeout_ms, GwHop *out, int max) {
    if (timeout_ms <= 0) timeout_ms = 400;
    int nc = (int)(sizeof(CANDIDATES) / sizeof(CANDIDATES[0]));
    if (nc <= 0) return 0;

    volatile LONG count = 0;
    int tcount = GW_THREADS;
    if (tcount > nc) tcount = nc;

    GwWorker w;
    w.self_ip = self_ip; w.local_gw = local_gw; w.timeout_ms = timeout_ms;
    w.out = out; w.count = &count; w.cap = (LONG)max;

    HANDLE th[GW_THREADS];
    GwWorker ws[GW_THREADS];
    for (int i = 0; i < tcount; i++) {
        ws[i] = w; ws[i].start = i; ws[i].step = tcount;
        th[i] = CreateThread(NULL, 0, gw_thread, &ws[i], 0, NULL);
    }
    WaitForMultipleObjects((DWORD)tcount, th, TRUE, INFINITE);
    for (int i = 0; i < tcount; i++) CloseHandle(th[i]);
    return (int)count;
}

/* ---- HTTP title -> brand ---- */

static const char *ci_find(const char *hay, const char *needle) {
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++) {
        int ok = 1;
        for (size_t i = 0; i < nl; i++) {
            if (!p[i]) return NULL;
            if (ascii_lower((unsigned char)p[i]) != ascii_lower((unsigned char)needle[i])) { ok = 0; break; }
        }
        if (ok) return p;
    }
    return NULL;
}

static void map_brand(const char *title, char *out, size_t n) {
    out[0] = 0;
    if (!title || !title[0]) return;
    if (strstr(title, "移动")) { snprintf(out, n, "光猫·中国移动"); return; }
    if (strstr(title, "电信")) { snprintf(out, n, "光猫·中国电信"); return; }
    if (strstr(title, "联通")) { snprintf(out, n, "光猫·中国联通"); return; }
    if (strstr(title, "华为") || ci_find(title, "huawei")) { snprintf(out, n, "华为路由"); return; }
    if (strstr(title, "小米") || ci_find(title, "xiaomi")) { snprintf(out, n, "小米路由"); return; }
    if (ci_find(title, "tp-link") || ci_find(title, "tplink")) { snprintf(out, n, "TP-Link"); return; }
    if (ci_find(title, "tenda") || strstr(title, "腾达")) { snprintf(out, n, "Tenda"); return; }
    if (ci_find(title, "netgear")) { snprintf(out, n, "NETGEAR"); return; }
    if (ci_find(title, "zte") || strstr(title, "中兴")) { snprintf(out, n, "中兴"); return; }
}

static char *http_get_body(uint32_t ip, int timeout_s) {
    char ipbuf[16];
    ip_to_string(ip, ipbuf, sizeof(ipbuf));
    WCHAR wh[64];
    MultiByteToWideChar(CP_ACP, 0, ipbuf, -1, wh, 64);

    HINTERNET ses = WinHttpOpen(L"lanmgr/0.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!ses) return NULL;
    WinHttpSetTimeouts(ses, 3000, 3000, 5000, timeout_s * 1000);
    HINTERNET con = WinHttpConnect(ses, wh, 80, 0);
    if (!con) { WinHttpCloseHandle(ses); return NULL; }
    HINTERNET req = WinHttpOpenRequest(con, L"GET", L"/", NULL, NULL, NULL, 0);
    if (!req) { WinHttpCloseHandle(con); WinHttpCloseHandle(ses); return NULL; }

    char *result = NULL;
    if (WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0) &&
        WinHttpReceiveResponse(req, NULL)) {
        size_t cap = 8192, n = 0;
        char *b = (char *)malloc(cap);
        if (b) {
            DWORD avail = 0, read = 0;
            for (;;) {
                if (!WinHttpQueryDataAvailable(req, &avail)) break;
                if (avail == 0) break;
                while (n + avail + 1 > cap) { cap *= 2; b = (char *)realloc(b, cap); }
                if (!WinHttpReadData(req, b + n, avail, &read)) break;
                n += read;
            }
            b[n] = 0;
            result = b;
        }
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    return result;
}

int gateway_brand(uint32_t ip, char *out, size_t outlen) {
    if (out && outlen) out[0] = 0;
    char *body = http_get_body(ip, 2);
    if (!body) return E_IO;

    const char *ts = ci_find(body, "<title");
    if (ts) {
        const char *gt = strchr(ts, '>');
        if (gt) {
            const char *end = ci_find(gt + 1, "</title");
            if (!end) end = gt + 1 + strlen(gt + 1);
            size_t len = (size_t)(end - (gt + 1));
            char title[512];
            size_t cplen = len < (sizeof(title) - 1) ? len : (sizeof(title) - 1);
            memcpy(title, gt + 1, cplen);
            title[cplen] = 0;
            map_brand(title, out, outlen);
        }
    }
    free(body);
    return E_OK;
}
