#include "wincompat.h"
#include "rollback.h"
#include "util.h"
#include "error.h"
#include "log.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ROLLBACK 256

static RollbackEntry g_items[MAX_ROLLBACK];
static int g_count = 0;
static char g_path[512];
static CRITICAL_SECTION g_lock;
static int g_inited = 0;

static int inited(void) {
    if (!g_inited) { InitializeCriticalSection(&g_lock); g_inited = 1; }
    return g_inited;
}

/* ---------- JSON (de)serialization ---------- */

static cJSON *entry_to_json(const RollbackEntry *e) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "id", e->id);
    cJSON_AddNumberToObject(o, "created_ms", (double)e->created_ms);
    cJSON_AddStringToObject(o, "kind", e->kind);
    cJSON_AddStringToObject(o, "target", e->target);
    cJSON_AddStringToObject(o, "summary", e->summary);
    cJSON_AddStringToObject(o, "mode", e->mode);
    cJSON_AddStringToObject(o, "rkind", e->rkind);
    cJSON_AddStringToObject(o, "rcmd", e->rcmd);
    cJSON_AddStringToObject(o, "rip", e->rip);
    cJSON_AddStringToObject(o, "rcred", e->rcred);
    cJSON_AddNumberToObject(o, "resc", e->resc);
    cJSON_AddStringToObject(o, "cred_id", e->cred_id);
    cJSON_AddNumberToObject(o, "status", e->status);
    cJSON_AddNumberToObject(o, "rolled_ms", (double)e->rolled_ms);
    return o;
}

static const char *jstr(const cJSON *o, const char *k, const char *def) {
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(o, k);
    return (cJSON_IsString(it) && it->valuestring) ? it->valuestring : def;
}
static int64_t jint(const cJSON *o, const char *k, int64_t def) {
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(o, k);
    return cJSON_IsNumber(it) ? (int64_t)it->valuedouble : def;
}
static void setstr(char *d, size_t n, const char *s) { snprintf(d, n, "%s", s ? s : ""); }

static void json_to_entry(const cJSON *o, RollbackEntry *e) {
    memset(e, 0, sizeof(*e));
    setstr(e->id, sizeof(e->id), jstr(o, "id", ""));
    e->created_ms = jint(o, "created_ms", 0);
    setstr(e->kind, sizeof(e->kind), jstr(o, "kind", ""));
    setstr(e->target, sizeof(e->target), jstr(o, "target", ""));
    setstr(e->summary, sizeof(e->summary), jstr(o, "summary", ""));
    setstr(e->mode, sizeof(e->mode), jstr(o, "mode", "semi"));
    setstr(e->rkind, sizeof(e->rkind), jstr(o, "rkind", ""));
    setstr(e->rcmd, sizeof(e->rcmd), jstr(o, "rcmd", ""));
    setstr(e->rip, sizeof(e->rip), jstr(o, "rip", ""));
    setstr(e->rcred, sizeof(e->rcred), jstr(o, "rcred", ""));
    e->resc = (int)jint(o, "resc", 0);
    setstr(e->cred_id, sizeof(e->cred_id), jstr(o, "cred_id", ""));
    e->status = (int)jint(o, "status", 0);
    e->rolled_ms = jint(o, "rolled_ms", 0);
}

/* ---------- file persistence ---------- */

static void append_file(const RollbackEntry *e) {
    if (!g_path[0]) return;
    cJSON *o = entry_to_json(e);
    char *s = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    if (!s) return;
    FILE *f = fopen(g_path, "a");
    if (f) { fputs(s, f); fputs("\n", f); fclose(f); }
    free(s);
}

static void rewrite_file(void) {
    if (!g_path[0]) return;
    FILE *f = fopen(g_path, "wb");
    if (!f) return;
    for (int i = 0; i < g_count; i++) {
        cJSON *o = entry_to_json(&g_items[i]);
        char *s = cJSON_PrintUnformatted(o);
        cJSON_Delete(o);
        if (s) { fputs(s, f); fputs("\n", f); free(s); }
    }
    fclose(f);
}

/* ---------- public API ---------- */

int rollback_init(const char *path) {
    inited();
    EnterCriticalSection(&g_lock);
    snprintf(g_path, sizeof(g_path), "%s", path ? path : "rollback.log");
    g_count = 0;

    FILE *f = fopen(g_path, "rb");
    if (f) {
        char line[8192];
        while (fgets(line, sizeof(line), f)) {
            if (g_count >= MAX_ROLLBACK) break;
            cJSON *o = cJSON_Parse(line);
            if (o) { json_to_entry(o, &g_items[g_count]); cJSON_Delete(o); g_count++; }
        }
        fclose(f);
    }
    LeaveCriticalSection(&g_lock);
    return 0;
}

int rollback_record(const RollbackEntry *e, char *out_id, size_t out_id_len) {
    inited();
    if (!e) return E_ARG;
    int rc = E_OK;
    EnterCriticalSection(&g_lock);
    if (g_count >= MAX_ROLLBACK) { rc = E_INTERNAL; }
    else {
        RollbackEntry *d = &g_items[g_count++];
        *d = *e;
        if (!d->id[0]) gen_id(d->id, sizeof(d->id));
        if (d->created_ms == 0) d->created_ms = now_ms();
        d->status = ROLLBACK_APPLIED;
        if (!d->mode[0]) snprintf(d->mode, sizeof(d->mode), "semi");
        if (out_id && out_id_len) snprintf(out_id, out_id_len, "%s", d->id);
        append_file(d);
    }
    LeaveCriticalSection(&g_lock);
    return rc;
}

int rollback_list(RollbackEntry *out, int max) {
    inited();
    int k = 0;
    EnterCriticalSection(&g_lock);
    for (int i = g_count - 1; i >= 0 && k < max; i--) out[k++] = g_items[i];
    LeaveCriticalSection(&g_lock);
    return k;
}

int rollback_applied_count(void) {
    inited();
    int n = 0;
    EnterCriticalSection(&g_lock);
    for (int i = 0; i < g_count; i++) if (g_items[i].status == ROLLBACK_APPLIED) n++;
    LeaveCriticalSection(&g_lock);
    return n;
}

int rollback_get(const char *id, RollbackEntry *out) {
    inited();
    int rc = E_NOTFOUND;
    EnterCriticalSection(&g_lock);
    for (int i = 0; i < g_count; i++) {
        if (strcmp(g_items[i].id, id) == 0) { if (out) *out = g_items[i]; rc = E_OK; break; }
    }
    LeaveCriticalSection(&g_lock);
    return rc;
}

int rollback_mark(const char *id, int status) {
    inited();
    int rc = E_NOTFOUND;
    EnterCriticalSection(&g_lock);
    for (int i = 0; i < g_count; i++) {
        if (strcmp(g_items[i].id, id) == 0) {
            g_items[i].status = status;
            g_items[i].rolled_ms = now_ms();
            rc = E_OK;
            break;
        }
    }
    if (rc == E_OK) rewrite_file();
    LeaveCriticalSection(&g_lock);
    return rc;
}