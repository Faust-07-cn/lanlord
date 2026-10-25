#include "wincompat.h"
#include "server.h"
#include "core/jobs.h"
#include "core/log.h"
#include "core/util.h"
#include "core/error.h"
#include "net/topo.h"
#include "sec/risk.h"
#include "sec/audit.h"
#include "exec/exec.h"
#include "agent/agent.h"
#include "agent/tools.h"
#include "agent/provider.h"
#include "sec/keystore.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define LANMGR_VERSION "0.1.0"
#define MAX_REQ 65536

static const Config *g_cfg;
static Vault *g_vault;

static char *g_topology = NULL;      /* cached topology JSON (UTF-8) */
static CRITICAL_SECTION g_topo_lock;

/* ---------- small helpers ---------- */

static void send_resp(SOCKET s, int code, const char *ctype, const char *body, size_t len) {
    const char *reason = code == 200 ? "OK" : (code == 404 ? "Not Found" : "Bad Request");
    char hdr[512];
    snprintf(hdr, sizeof(hdr),
             "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n"
             "Cache-Control: no-store\r\n\r\n",
             code, reason, ctype, len);
    send(s, hdr, (int)strlen(hdr), 0);
    if (body && len) send(s, body, (int)len, 0);
}

static void send_json(SOCKET s, cJSON *o) {
    char *t = cJSON_PrintUnformatted(o);
    send_resp(s, 200, "application/json; charset=utf-8", t ? t : "{}", t ? strlen(t) : 2);
    if (t) free(t);
}

static void send_json_str(SOCKET s, const char *json_text) {
    send_resp(s, 200, "application/json; charset=utf-8", json_text, strlen(json_text));
}

static void send_err(SOCKET s, int code, const char *msg) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "error", msg);
    char *t = cJSON_PrintUnformatted(o);
    send_resp(s, code, "application/json; charset=utf-8", t, strlen(t));
    free(t); cJSON_Delete(o);
}

static const char *ext_ctype(const char *path) {
    const char *d = strrchr(path, '.');
    if (!d) return "text/plain; charset=utf-8";
    if (!strcmp(d, ".html")) return "text/html; charset=utf-8";
    if (!strcmp(d, ".js")) return "text/javascript; charset=utf-8";
    if (!strcmp(d, ".css")) return "text/css; charset=utf-8";
    if (!strcmp(d, ".svg")) return "image/svg+xml";
    if (!strcmp(d, ".png")) return "image/png";
    return "application/octet-stream";
}

/* Serve a static file from web_root (reject path traversal). */
static void serve_static(SOCKET s, const char *path) {
    if (strstr(path, "..")) { send_err(s, 404, "not found"); return; }
    if (!strcmp(path, "/")) path = "/index.html";
    char full[1024];
    snprintf(full, sizeof(full), "%s%s", g_cfg->web_root, path);
    FILE *f = fopen(full, "rb");
    if (!f) { send_err(s, 404, "not found"); return; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 0 || sz > (4 << 20)) { fclose(f); send_err(s, 404, "too big"); return; }
    char *buf = (char *)malloc((size_t)sz + 1);
    fread(buf, 1, (size_t)sz, f); fclose(f);
    send_resp(s, 200, ext_ctype(path), buf, (size_t)sz);
    free(buf);
}

/* ---------- job run functions (background) ---------- */

typedef struct { Vault *v; int mode; char ip[64]; char cred_id[40]; char cmd[4096]; int escalate; } ExecCtx;
static int exec_job_run(Job *j, char *out, size_t n) {
    ExecCtx *e = (ExecCtx *)j->ctx;
    ExecOpts o = {e->escalate != 0, 25};
    if (e->mode == 0) return exec_local_run(e->cmd, &o, out, n);
    return exec_remote_run(e->v, e->ip, e->cred_id, e->cmd, &o, out, n);
}
static void exec_job_cleanup(void *ctx) { free(ctx); }

typedef struct { Vault *v; const Config *cfg; char requirement[4096]; } AgentCtx;
static int agent_job_run(Job *j, char *out, size_t n) {
    AgentCtx *a = (AgentCtx *)j->ctx;
    return agent_run(a->v, a->cfg, a->requirement, out, n);
}
static void agent_job_cleanup(void *ctx) { free(ctx); }

static int discover_job_run(Job *j, char *out, size_t n) {
    (void)j;
    char *json = net_discover(g_cfg->scan_timeout_ms, g_cfg->scan_max_hosts);
    if (!json) return E_INTERNAL;
    snprintf(out, n, "%s", json);
    EnterCriticalSection(&g_topo_lock);
    free(g_topology);
    g_topology = json;
    LeaveCriticalSection(&g_topo_lock);
    return 0;
}

/* ---------- API handlers ---------- */

static void api_status(SOCKET s) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "version", LANMGR_VERSION);
    cJSON_AddBoolToObject(o, "ssh", ssh_available() ? 1 : 0);

    ProviderList pl;
    provider_list_load(g_cfg->providers_path, &pl);
    AgentProvider *p = provider_active(&pl);
    bool has_key = false;
    if (p) {
        char keys[64][64]; int nk = keystore_list(g_cfg->apikeys_path, keys, 64);
        for (int k = 0; k < nk; k++) if (!strcmp(keys[k], p->name)) { has_key = true; break; }
    }
    cJSON_AddStringToObject(o, "provider", p && p->name[0] ? p->name : "");
    cJSON_AddStringToObject(o, "model", p ? p->model : "");
    cJSON_AddBoolToObject(o, "agent_ready", (p && has_key) ? 1 : 0);
    send_json(s, o);
    cJSON_Delete(o);
}

static void api_topology(SOCKET s) {
    EnterCriticalSection(&g_topo_lock);
    const char *t = g_topology ? g_topology : "{}";
    send_json_str(s, t);
    LeaveCriticalSection(&g_topo_lock);
}

static void api_discover(SOCKET s) {
    Job *j = jobs_submit("discover", NULL, discover_job_run, NULL);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "job_id", j ? j->id : -1);
    send_json(s, o);
    cJSON_Delete(o);
}

static void api_confirmations(SOCKET s) {
    Confirmation cs[64];
    int n = risk_pending(cs, 64);
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < n; i++) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "id", cs[i].id);
        cJSON_AddNumberToObject(o, "level", (int)cs[i].level);
        cJSON_AddStringToObject(o, "summary", cs[i].summary);
        cJSON_AddNumberToObject(o, "timeout_s", cs[i].timeout_s);
        cJSON_AddNumberToObject(o, "created_ms", (double)cs[i].created_ms);
        cJSON_AddItemToArray(arr, o);
    }
    send_json(s, arr);
    cJSON_Delete(arr);
}

static void api_confirm(SOCKET s, cJSON *body) {
    cJSON *id = cJSON_GetObjectItemCaseSensitive(body, "id");
    cJSON *ap = cJSON_GetObjectItemCaseSensitive(body, "approve");
    if (!cJSON_IsString(id)) { send_err(s, 400, "id required"); return; }
    bool approve = cJSON_IsTrue(ap);

    Confirmation cf;
    if (risk_get(id->valuestring, &cf) != E_OK) { send_err(s, 404, "confirmation not found"); return; }
    if (cf.decided != 0) { send_err(s, 400, "already decided"); return; }

    risk_decide(id->valuestring, approve);
    audit_log("web", "confirm", id->valuestring, approve ? "approved" : "denied", cf.summary);

    if (approve) {
        /* action encoded in detail JSON: {"kind":"exec","mode":0|1,"ip":...,"cred_id":...,"command":...,"escalate":...} */
        cJSON *d = cJSON_Parse(cf.detail);
        if (d) {
            cJSON *kind = cJSON_GetObjectItemCaseSensitive(d, "kind");
            if (kind && cJSON_IsString(kind) && !strcmp(kind->valuestring, "exec")) {
                ExecCtx *e = (ExecCtx *)calloc(1, sizeof(ExecCtx));
                e->v = g_vault;
                e->mode = cJSON_IsNumber(cJSON_GetObjectItemCaseSensitive(d, "mode"))
                          ? cJSON_GetObjectItemCaseSensitive(d, "mode")->valueint : 0;
                const cJSON *c_ip = cJSON_GetObjectItemCaseSensitive(d, "ip");
                const cJSON *c_cr = cJSON_GetObjectItemCaseSensitive(d, "cred_id");
                const cJSON *c_cmd = cJSON_GetObjectItemCaseSensitive(d, "command");
                const cJSON *c_es = cJSON_GetObjectItemCaseSensitive(d, "escalate");
                snprintf(e->ip, sizeof(e->ip), "%s", cJSON_IsString(c_ip) ? c_ip->valuestring : "");
                snprintf(e->cred_id, sizeof(e->cred_id), "%s", cJSON_IsString(c_cr) ? c_cr->valuestring : "");
                snprintf(e->cmd, sizeof(e->cmd), "%s", cJSON_IsString(c_cmd) ? c_cmd->valuestring : "");
                e->escalate = cJSON_IsTrue(c_es) ? 1 : 0;
                Job *j = jobs_submit("exec", e, exec_job_run, exec_job_cleanup);
                cJSON_Delete(d);
                cJSON *r = cJSON_CreateObject();
                cJSON_AddStringToObject(r, "status", "approved");
                cJSON_AddNumberToObject(r, "job_id", j ? j->id : -1);
                send_json(s, r);
                cJSON_Delete(r);
                return;
            }
            cJSON_Delete(d);
        }
        cJSON *r = cJSON_CreateObject();
        cJSON_AddStringToObject(r, "status", "approved");
        send_json(s, r);
        cJSON_Delete(r);
        return;
    }

    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "denied");
    send_json(s, r);
    cJSON_Delete(r);
}

static void api_exec(SOCKET s, cJSON *body) {
    const char *mode = "local"; int m = 0;
    cJSON *mo = cJSON_GetObjectItemCaseSensitive(body, "mode");
    if (cJSON_IsString(mo)) { mode = mo->valuestring; if (!strcmp(mode, "remote")) m = 1; }

    const char *ip = ""; const char *cred = ""; const char *cmd = ""; int esc = 0;
    cJSON *tmp;
    if ((tmp = cJSON_GetObjectItemCaseSensitive(body, "ip")) && cJSON_IsString(tmp)) ip = tmp->valuestring;
    if ((tmp = cJSON_GetObjectItemCaseSensitive(body, "cred_id")) && cJSON_IsString(tmp)) cred = tmp->valuestring;
    if ((tmp = cJSON_GetObjectItemCaseSensitive(body, "command")) && cJSON_IsString(tmp)) cmd = tmp->valuestring;
    if ((tmp = cJSON_GetObjectItemCaseSensitive(body, "escalate")) && cJSON_IsTrue(tmp)) esc = 1;

    if (!cmd[0]) { send_err(s, 400, "command required"); return; }

    RiskLevel lvl = esc ? RISK_DESTRUCTIVE : RISK_WRITE;
    /* detail carries the action; the server executes it on approval. */
    cJSON *d = cJSON_CreateObject();
    cJSON_AddStringToObject(d, "kind", "exec");
    cJSON_AddNumberToObject(d, "mode", m);
    cJSON_AddStringToObject(d, "ip", ip);
    cJSON_AddStringToObject(d, "cred_id", cred);
    cJSON_AddStringToObject(d, "command", cmd);
    cJSON_AddBoolToObject(d, "escalate", esc ? 1 : 0);
    char *dd = cJSON_PrintUnformatted(d);
    cJSON_Delete(d);

    char summary[512];
    snprintf(summary, sizeof(summary), "执行命令：%s", cmd);
    Confirmation c;
    risk_request(lvl, summary, dd, g_cfg->confirm_timeout_s, &c);
    free(dd);
    audit_log("web", "exec-request", m ? ip : "local", "pending", cmd);

    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "confirm_id", c.id);
    cJSON_AddStringToObject(o, "summary", summary);
    send_json(s, o);
    cJSON_Delete(o);
}

static void api_credentials_get(SOCKET s) {
    CredPlain list[64];
    int n = vault_list(g_vault, list, 64);
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < n; i++) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "id", list[i].id);
        cJSON_AddStringToObject(o, "type", cred_type_str(list[i].type));
        cJSON_AddStringToObject(o, "label", list[i].label);
        cJSON_AddStringToObject(o, "target", list[i].target);
        cJSON_AddItemToArray(arr, o);
    }
    send_json(s, arr);
    cJSON_Delete(arr);
}

static void api_credentials_post(SOCKET s, cJSON *body) {
    const char *label = ""; const char *type = "ssh"; const char *target = ""; const char *user = ""; const char *secret = "";
    cJSON *tmp;
    if ((tmp = cJSON_GetObjectItemCaseSensitive(body, "label")) && cJSON_IsString(tmp)) label = tmp->valuestring;
    if ((tmp = cJSON_GetObjectItemCaseSensitive(body, "type")) && cJSON_IsString(tmp)) type = tmp->valuestring;
    if ((tmp = cJSON_GetObjectItemCaseSensitive(body, "target")) && cJSON_IsString(tmp)) target = tmp->valuestring;
    if ((tmp = cJSON_GetObjectItemCaseSensitive(body, "username")) && cJSON_IsString(tmp)) user = tmp->valuestring;
    if ((tmp = cJSON_GetObjectItemCaseSensitive(body, "secret")) && cJSON_IsString(tmp)) secret = tmp->valuestring;

    if (!secret[0]) { send_err(s, 400, "secret required"); return; }
    if (secret) log_redact(secret);

    CredPlain c; memset(&c, 0, sizeof(c));
    snprintf(c.label, sizeof(c.label), "%s", label);
    c.type = CRED_SSH;
    if (!strcmp(type, "winrm")) c.type = CRED_WINRM;
    else if (!strcmp(type, "http")) c.type = CRED_HTTP;
    else if (!strcmp(type, "apitoken")) c.type = CRED_APITOKEN;
    snprintf(c.target, sizeof(c.target), "%s", target);
    snprintf(c.username, sizeof(c.username), "%s", user);
    snprintf(c.secret, sizeof(c.secret), "%s", secret);
    int rc = vault_store(g_vault, &c);
    char id[40]; snprintf(id, sizeof(id), "%s", c.id);
    cred_zeroize(&c);
    if (rc != E_OK) { send_err(s, 500, "store failed"); return; }

    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "status", "stored");
    cJSON_AddStringToObject(o, "id", id);
    send_json(s, o);
    cJSON_Delete(o);
}

static void api_providers_get(SOCKET s) {
    ProviderList pl;
    provider_list_load(g_cfg->providers_path, &pl);
    char keys[64][64]; int nk = keystore_list(g_cfg->apikeys_path, keys, 64);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "active", pl.active);
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < pl.count; i++) {
        AgentProvider *p = &pl.items[i];
        bool has = false;
        for (int k = 0; k < nk; k++) if (!strcmp(keys[k], p->name)) { has = true; break; }
        cJSON *po = cJSON_CreateObject();
        cJSON_AddStringToObject(po, "name", p->name);
        cJSON_AddStringToObject(po, "base_url", p->base_url);
        cJSON_AddStringToObject(po, "endpoint", p->endpoint);
        cJSON_AddStringToObject(po, "model", p->model);
        cJSON_AddBoolToObject(po, "has_key", has ? 1 : 0);
        cJSON_AddItemToArray(arr, po);
    }
    cJSON_AddItemToObject(o, "providers", arr);
    send_json(s, o);
    cJSON_Delete(o);
}

static void api_providers_post(SOCKET s, cJSON *body) {
    const char *name = ""; const char *base = ""; const char *ep = ""; const char *model = "";
    cJSON *tmp;
    if ((tmp = cJSON_GetObjectItemCaseSensitive(body, "name")) && cJSON_IsString(tmp)) name = tmp->valuestring;
    if ((tmp = cJSON_GetObjectItemCaseSensitive(body, "base_url")) && cJSON_IsString(tmp)) base = tmp->valuestring;
    if ((tmp = cJSON_GetObjectItemCaseSensitive(body, "endpoint")) && cJSON_IsString(tmp)) ep = tmp->valuestring;
    if ((tmp = cJSON_GetObjectItemCaseSensitive(body, "model")) && cJSON_IsString(tmp)) model = tmp->valuestring;
    if (!name[0] || !base[0] || !ep[0]) { send_err(s, 400, "name/base_url/endpoint required"); return; }

    ProviderList pl;
    provider_list_load(g_cfg->providers_path, &pl);
    AgentProvider *p = provider_find(&pl, name);
    if (!p) {
        if (pl.count >= AGENT_MAX_PROVIDERS) { send_err(s, 400, "too many providers"); return; }
        p = &pl.items[pl.count++]; memset(p, 0, sizeof(*p));
        snprintf(p->name, sizeof(p->name), "%s", name);
    }
    snprintf(p->base_url, sizeof(p->base_url), "%s", base);
    snprintf(p->endpoint, sizeof(p->endpoint), "%s", ep);
    snprintf(p->model, sizeof(p->model), "%s", model);
    if (!pl.active[0]) snprintf(pl.active, sizeof(pl.active), "%s", name);
    provider_list_save(g_cfg->providers_path, &pl);

    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "status", "stored");
    send_json(s, o);
    cJSON_Delete(o);
}

static void api_provider_active(SOCKET s, cJSON *body) {
    const char *name = "";
    cJSON *tmp = cJSON_GetObjectItemCaseSensitive(body, "name");
    if (cJSON_IsString(tmp)) name = tmp->valuestring;
    if (!name[0]) { send_err(s, 400, "name required"); return; }
    ProviderList pl;
    provider_list_load(g_cfg->providers_path, &pl);
    if (!provider_find(&pl, name)) { send_err(s, 404, "provider not found"); return; }
    snprintf(pl.active, sizeof(pl.active), "%s", name);
    provider_list_save(g_cfg->providers_path, &pl);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "status", "active");
    cJSON_AddStringToObject(o, "active", name);
    send_json(s, o);
    cJSON_Delete(o);
}

static void api_provider_key(SOCKET s, cJSON *body) {
    const char *name = ""; const char *key = "";
    cJSON *tmp;
    if ((tmp = cJSON_GetObjectItemCaseSensitive(body, "name")) && cJSON_IsString(tmp)) name = tmp->valuestring;
    if ((tmp = cJSON_GetObjectItemCaseSensitive(body, "api_key")) && cJSON_IsString(tmp)) key = tmp->valuestring;
    if (!name[0] || !key[0]) { send_err(s, 400, "name/api_key required"); return; }
    log_redact(key);
    if (keystore_store(g_cfg->apikeys_path, name, key) != E_OK) { send_err(s, 500, "store failed"); return; }
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "status", "key-stored");
    send_json(s, o);
    cJSON_Delete(o);
}

static void api_provider_delete(SOCKET s, cJSON *body) {
    const char *name = "";
    cJSON *tmp = cJSON_GetObjectItemCaseSensitive(body, "name");
    if (cJSON_IsString(tmp)) name = tmp->valuestring;
    if (!name[0]) { send_err(s, 400, "name required"); return; }
    ProviderList pl;
    provider_list_load(g_cfg->providers_path, &pl);
    int idx = -1;
    for (int i = 0; i < pl.count; i++) if (!strcmp(pl.items[i].name, name)) { idx = i; break; }
    if (idx < 0) { send_err(s, 404, "provider not found"); return; }
    for (int i = idx; i < pl.count - 1; i++) pl.items[i] = pl.items[i + 1];
    pl.count--;
    if (pl.active[0] && !strcmp(pl.active, name)) { pl.active[0] = 0; if (pl.count) snprintf(pl.active, sizeof(pl.active), "%s", pl.items[0].name); }
    provider_list_save(g_cfg->providers_path, &pl);
    keystore_delete(g_cfg->apikeys_path, name);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "status", "deleted");
    send_json(s, o);
    cJSON_Delete(o);
}

static void api_agent(SOCKET s, cJSON *body) {
    cJSON *r = cJSON_GetObjectItemCaseSensitive(body, "requirement");
    if (!cJSON_IsString(r)) { send_err(s, 400, "requirement required"); return; }
    AgentCtx *a = (AgentCtx *)calloc(1, sizeof(AgentCtx));
    a->v = g_vault;
    a->cfg = g_cfg;
    snprintf(a->requirement, sizeof(a->requirement), "%s", r->valuestring);
    Job *j = jobs_submit("agent", a, agent_job_run, agent_job_cleanup);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "job_id", j ? j->id : -1);
    send_json(s, o);
    cJSON_Delete(o);
}

static void api_job(SOCKET s, const char *idstr) {
    int id = atoi(idstr);
    Job *j = jobs_find(id);
    cJSON *o = cJSON_CreateObject();
    if (!j) {
        cJSON_AddStringToObject(o, "status", "notfound");
    } else {
        int st = 0, pr = 0;
        jobs_status(j, &st, &pr);
        cJSON_AddStringToObject(o, "status", st == 2 ? "done" : (st == 3 ? "failed" : "running"));
        cJSON_AddNumberToObject(o, "progress", pr);
        cJSON_AddStringToObject(o, "result", jobs_result(j));
        cJSON_AddStringToObject(o, "error", jobs_error(j));
    }
    send_json(s, o);
    cJSON_Delete(o);
}

/* ---------- routing ---------- */

static void route(SOCKET s, const char *method, const char *path, const char *body) {
    if (!strcmp(method, "GET") && !strcmp(path, "/api/status")) { api_status(s); return; }
    if (!strcmp(method, "GET") && !strcmp(path, "/api/topology")) { api_topology(s); return; }
    if (!strcmp(method, "POST") && !strcmp(path, "/api/discover")) { api_discover(s); return; }
    if (!strcmp(method, "GET") && !strcmp(path, "/api/confirmations")) { api_confirmations(s); return; }
    if (!strcmp(method, "GET") && !strcmp(path, "/api/credentials")) { api_credentials_get(s); return; }
    if (!strcmp(method, "GET") && !strcmp(path, "/api/providers")) { api_providers_get(s); return; }

    if ((!strcmp(method, "POST") && !strcmp(path, "/api/confirm")) ||
        (!strcmp(method, "POST") && !strcmp(path, "/api/exec")) ||
        (!strcmp(method, "POST") && !strcmp(path, "/api/credentials")) ||
        (!strcmp(method, "POST") && !strcmp(path, "/api/agent")) ||
        (!strcmp(method, "POST") && !strcmp(path, "/api/providers")) ||
        (!strcmp(method, "POST") && !strcmp(path, "/api/provider/active")) ||
        (!strcmp(method, "POST") && !strcmp(path, "/api/provider/key")) ||
        (!strcmp(method, "POST") && !strcmp(path, "/api/provider/delete"))) {
        cJSON *b = NULL;
        if (body && body[0]) b = cJSON_Parse(body);
        if (!b) b = cJSON_CreateObject();
        if (!strcmp(path, "/api/confirm")) api_confirm(s, b);
        else if (!strcmp(path, "/api/exec")) api_exec(s, b);
        else if (!strcmp(path, "/api/credentials")) api_credentials_post(s, b);
        else if (!strcmp(path, "/api/providers")) api_providers_post(s, b);
        else if (!strcmp(path, "/api/provider/active")) api_provider_active(s, b);
        else if (!strcmp(path, "/api/provider/key")) api_provider_key(s, b);
        else if (!strcmp(path, "/api/provider/delete")) api_provider_delete(s, b);
        else api_agent(s, b);
        cJSON_Delete(b);
        return;
    }

    if (!strncmp(path, "/api/job/", 9)) { api_job(s, path + 9); return; }

    if (!strcmp(method, "GET")) { serve_static(s, path); return; }

    send_err(s, 404, "not found");
}

/* ---------- request reading ---------- */

static int recv_line(SOCKET s, char *buf, int cap) {
    int n = 0;
    char c;
    while (n < cap - 1) {
        int r = recv(s, &c, 1, 0);
        if (r <= 0) return -1;
        if (c == '\n') { if (n > 0 && buf[n-1] == '\r') n--; buf[n] = 0; return n; }
        buf[n++] = c;
    }
    return -1;
}

static void handle_client(SOCKET s) {
    int to = 10000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&to, sizeof(to));

    char line[8192];
    if (recv_line(s, line, sizeof(line)) < 0) return; /* request line */
    char method[16] = "", path[1024] = "", ver[16] = "";
    if (sscanf(line, "%15s %1023s %15s", method, path, ver) < 2) return;

    /* read headers until blank line */
    int content_length = 0;
    for (;;) {
        if (recv_line(s, line, sizeof(line)) < 0) return;
        if (line[0] == 0) break;
        if (!_strnicmp(line, "Content-Length:", 15)) content_length = atoi(line + 15);
    }

    char *body = NULL;
    if (content_length > 0 && content_length < MAX_REQ) {
        body = (char *)calloc(content_length + 1, 1);
        int got = 0;
        while (got < content_length) {
            int r = recv(s, body + got, content_length - got, 0);
            if (r <= 0) break;
            got += r;
        }
        body[got] = 0;
    }

    route(s, method, path, body ? body : "");
    free(body);
}

int web_server_run(const Config *cfg, Vault *vault) {
    g_cfg = cfg;
    g_vault = vault;
    InitializeCriticalSection(&g_topo_lock);
    jobs_init();

    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) { LOGE("socket failed"); return E_IO; }
    int one = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));

    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons((u_short)cfg->port);
    if (bind(ls, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        LOGE("bind 127.0.0.1:%d failed (err=%d)", cfg->port, WSAGetLastError());
        closesocket(ls); return E_IO;
    }
    if (listen(ls, 16) != 0) { closesocket(ls); return E_IO; }

    LOGI("Web 演示已启动: http://127.0.0.1:%d", cfg->port);

    /* initial topology scan on a background thread */
    jobs_submit("discover", NULL, discover_job_run, NULL);

    for (;;) {
        struct sockaddr_in ca; int clen = sizeof(ca);
        SOCKET cs = accept(ls, (struct sockaddr *)&ca, &clen);
        if (cs == INVALID_SOCKET) { Sleep(20); continue; }
        handle_client(cs);
        closesocket(cs);
    }
}
