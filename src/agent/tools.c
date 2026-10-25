#include "wincompat.h"
#include "tools.h"
#include "util.h"
#include "error.h"
#include "log.h"
#include "exec/exec.h"
#include "net/topo.h"
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---------- helpers ---------- */

static const char *jstr(const cJSON *o, const char *k) {
    if (!o) return NULL;
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(o, k);
    return cJSON_IsString(it) ? it->valuestring : NULL;
}
static int jboolv(const cJSON *o, const char *k, int def) {
    if (!o) return def;
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(o, k);
    if (cJSON_IsBool(it)) return cJSON_IsTrue(it) ? 1 : 0;
    return def;
}

/* One-shot ICMP ping. */
static bool ping_host(uint32_t ip, int timeout_ms) {
    HANDLE h = IcmpCreateFile();
    if (h == INVALID_HANDLE_VALUE) return false;
    BYTE reply[sizeof(ICMP_ECHO_REPLY) + 32];
    DWORD rc = IcmpSendEcho(h, (IPAddr)ip, NULL, 0, NULL, reply, sizeof(reply), (DWORD)timeout_ms);
    IcmpCloseHandle(h);
    return rc > 0 && ((ICMP_ECHO_REPLY *)reply)->Status == IP_SUCCESS;
}

/* ---------- handlers ---------- */

static int t_topology(const cJSON *a, ToolContext *ctx, char *out, size_t n) {
    (void)a;
    char *j = net_discover(ctx->cfg->scan_timeout_ms, ctx->cfg->scan_max_hosts);
    if (!j) { snprintf(out, n, "{\"error\":\"discover failed\"}"); return E_INTERNAL; }
    snprintf(out, n, "%s", j);
    free(j);
    return 0;
}

static int t_ping(const cJSON *a, ToolContext *ctx, char *out, size_t n) {
    (void)ctx;
    const char *ip = jstr(a, "ip");
    if (!ip) { snprintf(out, n, "{\"error\":\"missing ip\"}"); return E_ARG; }
    uint32_t addr = ip_from_string(ip);
    bool alive = addr ? ping_host(addr, 1000) : false;
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "ip", ip);
    cJSON_AddBoolToObject(o, "alive", alive ? 1 : 0);
    char *s = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    snprintf(out, n, "%s", s);
    free(s);
    return 0;
}

static int t_exec_local(const cJSON *a, ToolContext *ctx, char *out, size_t n) {
    (void)ctx;
    const char *cmd = jstr(a, "command");
    if (!cmd) { snprintf(out, n, "{\"error\":\"missing command\"}"); return E_ARG; }
    ExecOpts o = {false, 20};
    char buf[8192];
    int rc = exec_local_run(cmd, &o, buf, sizeof(buf));
    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "exit_code", rc);
    cJSON_AddStringToObject(r, "output", buf);
    char *s = cJSON_PrintUnformatted(r);
    cJSON_Delete(r);
    snprintf(out, n, "%s", s);
    free(s);
    return 0;
}

static RiskLevel exec_remote_risk(const cJSON *a) {
    return jboolv(a, "escalate", 0) ? RISK_DESTRUCTIVE : RISK_WRITE;
}

static int t_exec_remote(const cJSON *a, ToolContext *ctx, char *out, size_t n) {
    const char *ip = jstr(a, "ip");
    const char *cred = jstr(a, "cred_id");
    const char *cmd = jstr(a, "command");
    int escalate = jboolv(a, "escalate", 0);
    if (!ip || !cred || !cmd) { snprintf(out, n, "{\"error\":\"ip/cred_id/command required\"}"); return E_ARG; }
    ExecOpts o = {escalate != 0, 25};
    char buf[8192];
    int rc = exec_remote_run(ctx->vault, ip, cred, cmd, &o, buf, sizeof(buf));
    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "exit_code", rc);
    cJSON_AddStringToObject(r, "output", buf);
    char *s = cJSON_PrintUnformatted(r);
    cJSON_Delete(r);
    snprintf(out, n, "%s", s);
    free(s);
    return 0;
}

static int t_cred_list(const cJSON *a, ToolContext *ctx, char *out, size_t n) {
    (void)a;
    CredPlain list[64];
    int cnt = vault_list(ctx->vault, list, 64);
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < cnt; i++) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "id", list[i].id);
        cJSON_AddStringToObject(o, "type", cred_type_str(list[i].type));
        cJSON_AddStringToObject(o, "label", list[i].label);
        cJSON_AddStringToObject(o, "target", list[i].target);
        cJSON_AddItemToArray(arr, o);
    }
    char *s = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    snprintf(out, n, "%s", s ? s : "[]");
    if (s) free(s);
    return 0;
}

static int t_cred_add(const cJSON *a, ToolContext *ctx, char *out, size_t n) {
    const char *label = jstr(a, "label");
    const char *type = jstr(a, "type");
    const char *target = jstr(a, "target");
    const char *user = jstr(a, "username");
    const char *secret = jstr(a, "secret");
    if (!label || !secret) { snprintf(out, n, "{\"error\":\"label/secret required\"}"); return E_ARG; }

    if (secret) log_redact(secret);

    CredPlain c; memset(&c, 0, sizeof(c));
    snprintf(c.label, sizeof(c.label), "%s", label);
    c.type = CRED_SSH;
    if (type) {
        if (!strcmp(type, "winrm")) c.type = CRED_WINRM;
        else if (!strcmp(type, "http")) c.type = CRED_HTTP;
        else if (!strcmp(type, "apitoken")) c.type = CRED_APITOKEN;
    }
    snprintf(c.target, sizeof(c.target), "%s", target ? target : "");
    snprintf(c.username, sizeof(c.username), "%s", user ? user : "");
    snprintf(c.secret, sizeof(c.secret), "%s", secret);

    int rc = vault_store(ctx->vault, &c);
    char id[40]; snprintf(id, sizeof(id), "%s", c.id);
    cred_zeroize(&c);
    if (rc != E_OK) { snprintf(out, n, "{\"error\":\"vault store rc=%d\"}", rc); return rc; }
    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "stored");
    cJSON_AddStringToObject(r, "id", id);
    char *s = cJSON_PrintUnformatted(r);
    cJSON_Delete(r);
    snprintf(out, n, "%s", s);
    free(s);
    return 0;
}

/* ---------- registry ---------- */

#define TOOL(name, desc, schema, r, h) { name, desc, schema, r, NULL, h }
#define TOOL_DYN(name, desc, schema, r, rf, h) { name, desc, schema, r, rf, h }

static const ToolDef REGISTRY[] = {
    TOOL("topology.get",
         "获取局域网拓扑树（含上级路由器与活动设备，树状 JSON）。",
         "{\"type\":\"object\",\"properties\":{}}",
         RISK_READ, t_topology),
    TOOL("ping",
         "Ping 局域网内某台设备，判断是否在线。",
         "{\"type\":\"object\",\"properties\":{\"ip\":{\"type\":\"string\"}},\"required\":[\"ip\"]}",
         RISK_READ, t_ping),
    TOOL("exec.local",
         "在管理机本机执行一条命令（cmd.exe /c）。",
         "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"}},\"required\":[\"command\"]}",
         RISK_WRITE, t_exec_local),
    TOOL_DYN("exec.remote",
         "在局域网内某台设备上执行命令。Linux 设备走 SSH；escalate=true 时用 sudo 提权。",
         "{\"type\":\"object\",\"properties\":{\"ip\":{\"type\":\"string\"},\"cred_id\":{\"type\":\"string\"},\"command\":{\"type\":\"string\"},\"escalate\":{\"type\":\"boolean\"}},\"required\":[\"ip\",\"cred_id\",\"command\"]}",
         RISK_WRITE, exec_remote_risk, t_exec_remote),
    TOOL("credential.list",
         "列出已保存的凭据（仅标签与目标，不含密码）。",
         "{\"type\":\"object\",\"properties\":{}}",
         RISK_READ, t_cred_list),
    TOOL("credential.add",
         "新增一条设备凭据（密码经 DPAPI 加密存储）。",
         "{\"type\":\"object\",\"properties\":{\"label\":{\"type\":\"string\"},\"type\":{\"type\":\"string\"},\"target\":{\"type\":\"string\"},\"username\":{\"type\":\"string\"},\"secret\":{\"type\":\"string\"}},\"required\":[\"label\",\"secret\"]}",
         RISK_DESTRUCTIVE, t_cred_add),
};

int tools_count(void) { return (int)(sizeof(REGISTRY) / sizeof(REGISTRY[0])); }
const ToolDef *tools_at(int i) { return (i >= 0 && i < tools_count()) ? &REGISTRY[i] : NULL; }

const ToolDef *tools_find(const char *name) {
    for (int i = 0; i < tools_count(); i++) if (strcmp(REGISTRY[i].name, name) == 0) return &REGISTRY[i];
    return NULL;
}

cJSON *tools_schema_array(void) {
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < tools_count(); i++) {
        const ToolDef *t = &REGISTRY[i];
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "type", "function");
        cJSON *fn = cJSON_CreateObject();
        cJSON_AddStringToObject(fn, "name", t->name);
        cJSON_AddStringToObject(fn, "description", t->description);
        cJSON *params = cJSON_Parse(t->params_schema);
        if (params) cJSON_AddItemToObject(fn, "parameters", params);
        cJSON_AddItemToObject(o, "function", fn);
        cJSON_AddItemToArray(arr, o);
    }
    return arr;
}
