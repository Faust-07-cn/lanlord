#include "wincompat.h"
#include "audit.h"
#include "util.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static char g_path[512];
static CRITICAL_SECTION g_lock;
static int g_inited = 0;

static int inited(void) {
    if (!g_inited) { InitializeCriticalSection(&g_lock); g_inited = 1; }
    return g_inited;
}

int audit_init(const char *path) {
    inited();
    EnterCriticalSection(&g_lock);
    snprintf(g_path, sizeof(g_path), "%s", path ? path : "audit.log");
    LeaveCriticalSection(&g_lock);
    return 0;
}

static void js_escape(const char *in, char *out, size_t n) {
    size_t j = 0;
    for (const char *p = in; p && *p && j + 2 < n; p++) {
        char c = *p;
        if (c == '"' || c == '\\') { out[j++] = '\\'; out[j++] = c; }
        else if (c == '\n') { out[j++] = '\\'; out[j++] = 'n'; }
        else if (c == '\r') { /* skip */ }
        else out[j++] = c;
    }
    out[j] = 0;
}

void audit_log(const char *actor, const char *action, const char *target,
               const char *decision, const char *detail) {
    inited();
    SYSTEMTIME st; GetLocalTime(&st);
    char tbuf[48], a[128], ac[128], tg[256], de[64], dt[2048];
    snprintf(tbuf, sizeof(tbuf), "%04d-%02d-%02dT%02d:%02d:%02d.%03d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    js_escape(actor, a, sizeof(a));
    js_escape(action, ac, sizeof(ac));
    js_escape(target, tg, sizeof(tg));
    js_escape(decision, de, sizeof(de));
    js_escape(detail, dt, sizeof(dt));

    char line[4096];
    snprintf(line, sizeof(line),
             "{\"ts\":\"%s\",\"actor\":\"%s\",\"action\":\"%s\",\"target\":\"%s\",\"decision\":\"%s\",\"detail\":\"%s\"}\n",
             tbuf, a, ac, tg, de, dt);

    EnterCriticalSection(&g_lock);
    FILE *f = fopen(g_path, "a");
    if (f) { fputs(line, f); fclose(f); }
    LeaveCriticalSection(&g_lock);
}
