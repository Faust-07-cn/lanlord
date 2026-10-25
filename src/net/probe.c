#include "wincompat.h"
#include "probe.h"
#include "util.h"
#include "error.h"
#include "log.h"
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdlib.h>

#define PING_THREADS 64

typedef struct {
    uint32_t *hosts;        /* network-order host list */
    int n;
    int start, step;
    int timeout_ms;
    uint32_t *out;
    volatile LONG *count;
    LONG cap;
} ProbeWorker;

static DWORD WINAPI probe_thread(LPVOID p) {
    ProbeWorker *w = (ProbeWorker *)p;
    HANDLE icmp = IcmpCreateFile();
    if (icmp == INVALID_HANDLE_VALUE) return 0;

    BYTE reply[sizeof(ICMP_ECHO_REPLY) + 64];
    for (int i = w->start; i < w->n; i += w->step) {
        uint32_t ip = w->hosts[i];
        DWORD rc = IcmpSendEcho(icmp, (IPAddr)ip, NULL, 0, NULL, reply, sizeof(reply), (DWORD)w->timeout_ms);
        if (rc > 0 && ((ICMP_ECHO_REPLY *)reply)->Status == IP_SUCCESS) {
            LONG idx = InterlockedIncrement(w->count) - 1;
            if (idx < w->cap) w->out[idx] = ip;
        } else if (rc == 0) {
            /* IP_REQ_TIMED_OUT etc. within a host counts as alive sometimes; keep strict success only. */
            DWORD err = GetLastError();
            if (err != IP_REQ_TIMED_OUT && err != IP_GENERAL_FAILURE && err != IP_DEST_HOST_UNREACHABLE &&
                err != IP_DEST_NET_UNREACHABLE) {
                /* Treat unexpected as possibly-alive (some hosts drop ttl=0 replies differently). */
                LONG idx = InterlockedIncrement(w->count) - 1;
                if (idx < w->cap) w->out[idx] = ip;
            }
        }
    }
    IcmpCloseHandle(icmp);
    return 0;
}

int probe_sweep(const Subnet *sub, int timeout_ms, int max_hosts, AliveList *out) {
    memset(out, 0, sizeof(*out));
    if (sub->prefix < 24) {
        /* /8.. /23 are too large to sweep responsibly; rely on ARP. */
        LOGW("subnet %s/%d too large for full sweep; relying on ARP cache",
             ip_to_string(sub->ip, (char[16]){0}, 16), sub->prefix);
        return E_OK;
    }

    uint32_t base_host = ntohl(network_address(sub->ip, sub->prefix));
    uint32_t addrs = (uint32_t)(1u << (32 - sub->prefix)); /* 256 for /24 */
    uint32_t first = base_host + 1;
    uint32_t last  = base_host + addrs - 1;
    if (addrs <= 2) return E_OK; /* /31,/32: nothing to sweep */

    int n = 0;
    uint32_t *hosts = (uint32_t *)malloc((size_t)addrs * sizeof(uint32_t));
    if (!hosts) return E_NOMEM;

    for (uint32_t h = first; h < last; h++) { /* exclude network (.0) and broadcast (.255) */
        if (n >= max_hosts) break;
        hosts[n++] = htonl(h);
    }

    if (n <= 0) { free(hosts); return E_OK; }

    uint32_t *results = (uint32_t *)calloc((size_t)n, sizeof(uint32_t));
    if (!results) { free(hosts); return E_NOMEM; }
    volatile LONG count = 0;

    ProbeWorker w;
    w.hosts = hosts; w.n = n; w.timeout_ms = timeout_ms;
    w.out = results; w.count = &count; w.cap = (LONG)n;

    int tcount = PING_THREADS;
    if (tcount > n) tcount = n;
    HANDLE th[PING_THREADS];
    ProbeWorker ws[PING_THREADS];

    for (int i = 0; i < tcount; i++) {
        ws[i] = w; ws[i].start = i; ws[i].step = tcount;
        th[i] = CreateThread(NULL, 0, probe_thread, &ws[i], 0, NULL);
    }
    WaitForMultipleObjects((DWORD)tcount, th, TRUE, INFINITE);
    for (int i = 0; i < tcount; i++) CloseHandle(th[i]);

    out->count = (int)count;
    if (out->count > LANMGR_MAX_ALIVE) out->count = LANMGR_MAX_ALIVE;
    for (int i = 0; i < out->count; i++) out->ips[i] = results[i];

    free(results);
    free(hosts);
    LOGI("ping sweep: %d alive of %d probed", out->count, n);
    return E_OK;
}
