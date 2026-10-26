#include "config.h"
#include "util.h"
#include "log.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int jint(const cJSON *o, const char *k, int def) {
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(o, k);
    if (cJSON_IsNumber(it)) return it->valueint;
    return def;
}
static bool jbool(const cJSON *o, const char *k, bool def) {
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(o, k);
    if (cJSON_IsBool(it)) return cJSON_IsTrue(it) != 0;
    if (cJSON_IsNumber(it)) return it->valueint != 0;
    return def;
}
static const char *jstr(const cJSON *o, const char *k, const char *def) {
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(o, k);
    if (cJSON_IsString(it) && it->valuestring) return it->valuestring;
    return def;
}
static void setstr(char *dst, size_t n, const char *src) {
    snprintf(dst, n, "%s", src ? src : "");
}

void config_defaults(Config *c) {
    memset(c, 0, sizeof(*c));
    c->port = 8686;
    c->scan_max_hosts = 256;
    c->scan_timeout_ms = 400;
    c->confirm_timeout_s = 120;
    c->store_plaintext = false;
    c->trace_upstream = true;
    c->agent.enabled = false;
    c->agent.base_url[0] = 0;
    c->agent.model[0] = 0;
    c->agent.max_turns = 10;
    c->agent.timeout_s = 60;
    setstr(c->vault_path, sizeof(c->vault_path), "vault.dat");
    setstr(c->audit_path, sizeof(c->audit_path), "audit.log");
    setstr(c->log_path, sizeof(c->log_path), "lanmgr.log");
    setstr(c->web_root, sizeof(c->web_root), "web");
    setstr(c->providers_path, sizeof(c->providers_path), "providers.json");
    setstr(c->apikeys_path, sizeof(c->apikeys_path), "apikeys.dat");
}

int config_load(Config *c, const char *path) {
    config_defaults(c);

    FILE *f = fopen(path, "rb");
    if (!f) { LOGD("config not found at %s; using defaults", path); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > (1 << 20)) { fclose(f); LOGW("config unusable size; using defaults"); return -1; }

    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    size_t r = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[r] = 0;

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) { LOGW("config parse error; using defaults"); return -1; }

    c->port = jint(root, "port", c->port);
    c->scan_max_hosts = jint(root, "scan_max_hosts", c->scan_max_hosts);
    c->scan_timeout_ms = jint(root, "scan_timeout_ms", c->scan_timeout_ms);
    c->confirm_timeout_s = jint(root, "confirm_timeout_s", c->confirm_timeout_s);
    c->store_plaintext = jbool(root, "store_plaintext", c->store_plaintext);
    c->trace_upstream = jbool(root, "trace_upstream", c->trace_upstream);

    const cJSON *ag = cJSON_GetObjectItemCaseSensitive(root, "agent");
    if (cJSON_IsObject(ag)) {
        c->agent.enabled = jbool(ag, "enabled", c->agent.enabled);
        setstr(c->agent.base_url, sizeof(c->agent.base_url), jstr(ag, "base_url", c->agent.base_url));
        setstr(c->agent.model, sizeof(c->agent.model), jstr(ag, "model", c->agent.model));
        c->agent.max_turns = jint(ag, "max_turns", c->agent.max_turns);
        c->agent.timeout_s = jint(ag, "timeout_s", c->agent.timeout_s);
    }

    setstr(c->vault_path, sizeof(c->vault_path), jstr(root, "vault_path", c->vault_path));
    setstr(c->audit_path, sizeof(c->audit_path), jstr(root, "audit_path", c->audit_path));
    setstr(c->log_path, sizeof(c->log_path), jstr(root, "log_path", c->log_path));
    setstr(c->web_root, sizeof(c->web_root), jstr(root, "web_root", c->web_root));
    setstr(c->providers_path, sizeof(c->providers_path), jstr(root, "providers_path", c->providers_path));
    setstr(c->apikeys_path, sizeof(c->apikeys_path), jstr(root, "apikeys_path", c->apikeys_path));

    cJSON_Delete(root);

    if (c->store_plaintext) {
        LOGW("store_plaintext=TRUE was requested explicitly; secrets may be stored in plaintext");
    }
    return 0;
}

int config_save(const Config *c, const char *path) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "port", c->port);
    cJSON_AddNumberToObject(root, "scan_max_hosts", c->scan_max_hosts);
    cJSON_AddNumberToObject(root, "scan_timeout_ms", c->scan_timeout_ms);
    cJSON_AddNumberToObject(root, "confirm_timeout_s", c->confirm_timeout_s);
    cJSON_AddBoolToObject(root, "store_plaintext", c->store_plaintext ? 1 : 0);
    cJSON_AddBoolToObject(root, "trace_upstream", c->trace_upstream ? 1 : 0);

    cJSON *ag = cJSON_CreateObject();
    cJSON_AddBoolToObject(ag, "enabled", c->agent.enabled ? 1 : 0);
    cJSON_AddStringToObject(ag, "base_url", c->agent.base_url);
    cJSON_AddStringToObject(ag, "model", c->agent.model);
    cJSON_AddNumberToObject(ag, "max_turns", c->agent.max_turns);
    cJSON_AddNumberToObject(ag, "timeout_s", c->agent.timeout_s);
    cJSON_AddItemToObject(root, "agent", ag);

    cJSON_AddStringToObject(root, "vault_path", c->vault_path);
    cJSON_AddStringToObject(root, "audit_path", c->audit_path);
    cJSON_AddStringToObject(root, "log_path", c->log_path);
    cJSON_AddStringToObject(root, "web_root", c->web_root);
    cJSON_AddStringToObject(root, "providers_path", c->providers_path);
    cJSON_AddStringToObject(root, "apikeys_path", c->apikeys_path);

    char *s = cJSON_Print(root);
    cJSON_Delete(root);
    if (!s) return -1;

    FILE *f = fopen(path, "wb");
    if (!f) { free(s); return -1; }
    fwrite(s, 1, strlen(s), f);
    fclose(f);
    free(s);
    return 0;
}
