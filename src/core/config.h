#ifndef LANMGR_CONFIG_H
#define LANMGR_CONFIG_H

#include <stdbool.h>

typedef struct {
    int    port;               /* web listen port (demo binds 127.0.0.1) */
    int    scan_max_hosts;     /* upper bound for active ping sweep */
    int    scan_timeout_ms;    /* per-ping timeout */
    int    confirm_timeout_s;  /* risk-confirmation auto-deny timeout */
    bool   store_plaintext;    /* DEFAULT FALSE; explicit opt-in only */
    bool   trace_upstream;     /* traceroute to discover upstream routers */

    char   authorization[16];  /* Agent auth mode: "semi" | "full" */

    struct {
        bool   enabled;
        char   base_url[256];
        char   model[128];
        int    max_turns;
        int    timeout_s;
    } agent;

    char   vault_path[512];
    char   audit_path[512];
    char   log_path[512];
    char   web_root[512];
    char   providers_path[512];  /* Agent 提供方配置(调用/请求地址/模型) */
    char   apikeys_path[512];    /* 独立 API Key 密钥库(DPAPI 加密) */
    char   rollback_path[512];   /* Agent 回滚日志(JSON 行,可回滚操作历史) */
} Config;

void config_defaults(Config *c);

/* Load JSON config; on missing file returns 1, on parse error -1, on success 0. */
int  config_load(Config *c, const char *path);

/* Persist config as JSON. Returns 0 on success. */
int  config_save(const Config *c, const char *path);

#endif
