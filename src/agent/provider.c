#include "provider.h"
#include "util.h"
#include "error.h"
#include "log.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void provider_list_init(ProviderList *pl) {
    memset(pl, 0, sizeof(*pl));
}

static const char *jstr(const cJSON *o, const char *k) {
    const cJSON *it = o ? cJSON_GetObjectItemCaseSensitive(o, k) : NULL;
    return cJSON_IsString(it) ? it->valuestring : "";
}

int provider_list_load(const char *path, ProviderList *pl) {
    provider_list_init(pl);
    FILE *f = fopen(path, "rb");
    if (!f) return 1; /* not found */
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > (1 << 20)) { fclose(f); return -1; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    size_t r = fread(buf, 1, (size_t)sz, f); fclose(f); buf[r] = 0;

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) return -1;

    const cJSON *active = cJSON_GetObjectItemCaseSensitive(root, "active");
    if (cJSON_IsString(active)) snprintf(pl->active, sizeof(pl->active), "%s", active->valuestring);

    const cJSON *provs = cJSON_GetObjectItemCaseSensitive(root, "providers");
    if (cJSON_IsArray(provs)) {
        int n = cJSON_GetArraySize(provs);
        if (n > AGENT_MAX_PROVIDERS) n = AGENT_MAX_PROVIDERS;
        for (int i = 0; i < n; i++) {
            const cJSON *po = cJSON_GetArrayItem(provs, i);
            AgentProvider *p = &pl->items[pl->count++];
            memset(p, 0, sizeof(*p));
            snprintf(p->name, sizeof(p->name), "%s", jstr(po, "name"));
            snprintf(p->base_url, sizeof(p->base_url), "%s", jstr(po, "base_url"));
            snprintf(p->endpoint, sizeof(p->endpoint), "%s", jstr(po, "endpoint"));
            snprintf(p->model, sizeof(p->model), "%s", jstr(po, "model"));
        }
    }
    cJSON_Delete(root);
    return 0;
}

int provider_list_save(const char *path, const ProviderList *pl) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "active", pl->active);
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < pl->count; i++) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "name", pl->items[i].name);
        cJSON_AddStringToObject(o, "base_url", pl->items[i].base_url);
        cJSON_AddStringToObject(o, "endpoint", pl->items[i].endpoint);
        cJSON_AddStringToObject(o, "model", pl->items[i].model);
        cJSON_AddItemToArray(arr, o);
    }
    cJSON_AddItemToObject(root, "providers", arr);
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

AgentProvider *provider_find(ProviderList *pl, const char *name) {
    for (int i = 0; i < pl->count; i++) if (strcmp(pl->items[i].name, name) == 0) return &pl->items[i];
    return NULL;
}

AgentProvider *provider_active(ProviderList *pl) {
    if (pl->active[0]) {
        AgentProvider *p = provider_find(pl, pl->active);
        if (p) return p;
    }
    return pl->count > 0 ? &pl->items[0] : NULL;
}
