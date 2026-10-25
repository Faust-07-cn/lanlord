#ifndef LANMGR_PROVIDER_H
#define LANMGR_PROVIDER_H

#include <stdbool.h>

#define AGENT_MAX_PROVIDERS 16

typedef struct {
    char name[64];
    char base_url[256];   /* 调用地址：scheme://host[:port] */
    char endpoint[256];   /* 请求地址：完整路径，如 /v1/chat/completions */
    char model[128];      /* 模型名 */
} AgentProvider;

typedef struct {
    int count;
    AgentProvider items[AGENT_MAX_PROVIDERS];
    char active[64];      /* 当前使用的提供方名称 */
} ProviderList;

/* Load providers JSON. Returns 0 ok, 1 if file missing (empty list), -1 error. */
int provider_list_load(const char *path, ProviderList *pl);
int provider_list_save(const char *path, const ProviderList *pl);

AgentProvider *provider_find(ProviderList *pl, const char *name);
AgentProvider *provider_active(ProviderList *pl);   /* by name, else first item */
void provider_list_init(ProviderList *pl);

#endif
