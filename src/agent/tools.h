#ifndef LANMGR_TOOLS_H
#define LANMGR_TOOLS_H

#include "cJSON.h"
#include "sec/risk.h"
#include "sec/vault.h"
#include "core/config.h"
#include <stddef.h>

typedef struct {
    Vault *vault;
    const Config *cfg;
} ToolContext;

typedef struct {
    const char *name;
    const char *description;
    const char *params_schema;                 /* JSON Schema (static string) */
    RiskLevel risk;                            /* static risk */
    RiskLevel (*risk_of)(const cJSON *args);   /* optional dynamic risk */
    int (*handler)(const cJSON *args, ToolContext *ctx, char *out, size_t outlen);
} ToolDef;

int tools_count(void);
const ToolDef *tools_at(int i);
const ToolDef *tools_find(const char *name);

/* Build the "tools" array for an OpenAI-compatible request. Caller cJSON_Delete()s. */
cJSON *tools_schema_array(void);

/* Return the agent-supplied reverse command (args["rollback"]) for exec tools,
 * or NULL if absent/empty. Enables rollback for full-authorization auto-run. */
const char *tool_rollback_cmd(const ToolDef *td, const cJSON *args);

/* True if this tool call can be rolled back (exec.* with a reverse command,
 * or credential.add which auto-derives delete). */
int tool_is_rollbackable(const ToolDef *td, const cJSON *args);

#endif
