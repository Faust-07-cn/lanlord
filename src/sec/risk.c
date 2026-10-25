#include "wincompat.h"
#include "risk.h"
#include "util.h"
#include "error.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PENDING 64

static Confirmation g_pending[MAX_PENDING];
static int g_count = 0;
static CRITICAL_SECTION g_lock;
static int g_inited = 0;

int risk_init(void) {
    if (!g_inited) { InitializeCriticalSection(&g_lock); g_inited = 1; }
    return 0;
}

const char *risk_level_str(RiskLevel lvl) {
    switch (lvl) {
        case RISK_READ: return "只读";
        case RISK_WRITE: return "可写(需确认)";
        case RISK_DESTRUCTIVE: return "高危(需确认)";
    }
    return "未知";
}

const char *risk_level_json_str(RiskLevel lvl) {
    switch (lvl) {
        case RISK_READ: return "read";
        case RISK_WRITE: return "write";
        default: return "destructive";
    }
}

bool risk_requires_confirm(RiskLevel lvl) { return lvl != RISK_READ; }

static void expire_locked(int64_t now) {
    for (int i = 0; i < g_count; i++) {
        if (g_pending[i].decided == 0 &&
            g_pending[i].timeout_s > 0 &&
            now - g_pending[i].created_ms > (int64_t)g_pending[i].timeout_s * 1000) {
            g_pending[i].decided = 3; /* timeout -> auto deny */
            g_pending[i].decided_ms = now;
        }
    }
}

int risk_request(RiskLevel lvl, const char *summary, const char *detail_json, int timeout_s, Confirmation *out) {
    risk_init();
    EnterCriticalSection(&g_lock);
    expire_locked(now_ms());
    if (g_count >= MAX_PENDING) { LeaveCriticalSection(&g_lock); return E_INTERNAL; }
    Confirmation *c = &g_pending[g_count++];
    memset(c, 0, sizeof(*c));
    gen_id(c->id, sizeof(c->id));
    c->level = lvl;
    snprintf(c->summary, sizeof(c->summary), "%s", summary ? summary : "");
    snprintf(c->detail, sizeof(c->detail), "%s", detail_json ? detail_json : "");
    c->created_ms = now_ms();
    c->timeout_s = timeout_s > 0 ? timeout_s : 120;
    c->decided = 0;
    if (out) *out = *c;
    LeaveCriticalSection(&g_lock);
    return E_OK;
}

int risk_query(const char *id, int *decided) {
    risk_init();
    int d = -1;
    EnterCriticalSection(&g_lock);
    expire_locked(now_ms());
    for (int i = 0; i < g_count; i++) {
        if (strcmp(g_pending[i].id, id) == 0) { d = g_pending[i].decided; break; }
    }
    LeaveCriticalSection(&g_lock);
    if (decided) *decided = d;
    return d < 0 ? E_NOTFOUND : E_OK;
}

int risk_get(const char *id, Confirmation *out) {
    risk_init();
    int rc = E_NOTFOUND;
    EnterCriticalSection(&g_lock);
    for (int i = 0; i < g_count; i++) {
        if (strcmp(g_pending[i].id, id) == 0) { if (out) *out = g_pending[i]; rc = E_OK; break; }
    }
    LeaveCriticalSection(&g_lock);
    return rc;
}

int risk_decide(const char *id, bool approve) {
    risk_init();
    int rc = E_NOTFOUND;
    EnterCriticalSection(&g_lock);
    for (int i = 0; i < g_count; i++) {
        if (g_pending[i].decided == 0 && strcmp(g_pending[i].id, id) == 0) {
            g_pending[i].decided = approve ? 1 : 2;
            g_pending[i].decided_ms = now_ms();
            rc = E_OK;
            break;
        }
    }
    LeaveCriticalSection(&g_lock);
    return rc;
}

int risk_pending(Confirmation *out, int max) {
    risk_init();
    int k = 0;
    EnterCriticalSection(&g_lock);
    expire_locked(now_ms());
    for (int i = 0; i < g_count && k < max; i++) {
        if (g_pending[i].decided == 0) out[k++] = g_pending[i];
    }
    LeaveCriticalSection(&g_lock);
    return k;
}
