#include "wincompat.h"
#include "agent.h"
#include "tools.h"
#include "llm_http.h"
#include "provider.h"
#include "util.h"
#include "error.h"
#include "log.h"
#include "sec/audit.h"
#include "sec/keystore.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static const char *jstr_get(const cJSON *o, const char *k) {
    if (!o) return NULL;
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(o, k);
    return cJSON_IsString(it) ? it->valuestring : NULL;
}

/* Build the full request URL from base_url + endpoint (normalizing the slash). */
static void build_url(const char *base, const char *ep, char *out, size_t n) {
    size_t blen = strlen(base);
    snprintf(out, n, "%s%s%s", base,
             (blen > 0 && base[blen - 1] == '/') ? "" : "/",
             (ep[0] == '/') ? ep + 1 : ep);
}

/* Wait for a confirmation; returns 1 approved, 0 denied/timeout. */
static int wait_confirm(const char *id, int timeout_s) {
    int64_t start = now_ms();
    while (now_ms() - start < (int64_t)timeout_s * 1000) {
        int d = 0;
        risk_query(id, &d);
        if (d == 1) return 1;
        if (d == 2 || d == 3) return 0;
        Sleep(100);
    }
    return 0;
}

int agent_run(Vault *v, const Config *cfg, const char *requirement, char *out, size_t outlen) {
    if (outlen) out[0] = 0;
    if (!v || !cfg || !requirement) return E_ARG;

    /* Load provider config (用户配置：调用地址 base_url + 请求地址 endpoint + 模型). */
    ProviderList pl;
    if (provider_list_load(cfg->providers_path, &pl) != 0 || pl.count == 0) {
        snprintf(out, outlen, "尚未配置 Agent 提供方：请先添加提供方(调用地址/请求地址/模型)并设置 API Key。");
        return E_UNSUPPORTED;
    }
    AgentProvider *p = provider_active(&pl);
    if (!p || !p->base_url[0] || !p->endpoint[0] || !p->model[0]) {
        snprintf(out, outlen, "当前提供方缺少 调用地址(base_url) 或 请求地址(endpoint) 或 模型(model)，请补全后重试。");
        return E_UNSUPPORTED;
    }

    char full_url[600];
    build_url(p->base_url, p->endpoint, full_url, sizeof(full_url));

    char api_key[512];
    api_key[0] = 0;
    if (keystore_get(cfg->apikeys_path, p->name, api_key, sizeof(api_key)) != E_OK || !api_key[0]) {
        snprintf(out, outlen, "提供方「%s」尚未设置 API Key（独立存储于 %s），请设置后重试。", p->name, cfg->apikeys_path);
        return E_AUTH;
    }
    log_redact(api_key);

    char answer[8192];
    answer[0] = 0;

    cJSON *messages = cJSON_CreateArray();
    cJSON *sys = cJSON_CreateObject();
    cJSON_AddStringToObject(sys, "role", "system");
    cJSON_AddStringToObject(sys, "content",
        "你是局域网管理系统(lanmgr)的内嵌管理 Agent。你只能调用提供的工具完成任务，不要虚构工具调用。"
        "状态变更/高危操作会触发生效前的人工确认，由用户在界面上批准或拒绝。用简洁中文答复用户。");
    cJSON_AddItemToArray(messages, sys);
    cJSON *usr = cJSON_CreateObject();
    cJSON_AddStringToObject(usr, "role", "user");
    cJSON_AddStringToObject(usr, "content", requirement);
    cJSON_AddItemToArray(messages, usr);

    cJSON *tools = tools_schema_array();
    ToolContext tctx;
    tctx.vault = v;
    tctx.cfg = cfg;

    int rc = E_OK;
    for (int turn = 0; turn < cfg->agent.max_turns; turn++) {
        cJSON *req = cJSON_CreateObject();
        cJSON_AddStringToObject(req, "model", cfg->agent.model);
        cJSON_AddItemReferenceToObject(req, "messages", messages);
        cJSON_AddItemReferenceToObject(req, "tools", tools);

        char *resp = llm_chat(full_url, api_key, p->model, req, cfg->agent.timeout_s);
        cJSON_Delete(req);

        if (!resp) {
            snprintf(answer, sizeof(answer), "请求 Agent 端点失败（请检查 base_url/网络/API Key）。");
            rc = E_NET;
            break;
        }

        cJSON *root = cJSON_Parse(resp);
        free(resp);
        if (!root) { snprintf(answer, sizeof(answer), "Agent 响应解析失败。"); rc = E_INTERNAL; break; }

        cJSON *choices = cJSON_GetObjectItemCaseSensitive(root, "choices");
        cJSON *choice = cJSON_IsArray(choices) ? cJSON_GetArrayItem(choices, 0) : NULL;
        cJSON *msg = choice ? cJSON_GetObjectItemCaseSensitive(choice, "message") : NULL;
        if (!msg) { cJSON_Delete(root); snprintf(answer, sizeof(answer), "Agent 返回空消息。"); break; }

        cJSON *tcs = cJSON_GetObjectItemCaseSensitive(msg, "tool_calls");

        if (cJSON_IsArray(tcs) && cJSON_GetArraySize(tcs) > 0) {
            /* Detach the assistant message (with tool_calls) and move it into messages. */
            cJSON_DetachItemViaPointer(choice, msg);
            cJSON_AddItemToArray(messages, msg);
            cJSON_Delete(root);

            int ntc = cJSON_GetArraySize(tcs);
            for (int i = 0; i < ntc; i++) {
                cJSON *tc = cJSON_GetArrayItem(tcs, i);
                const char *tc_id = jstr_get(tc, "id");
                cJSON *fn = cJSON_GetObjectItemCaseSensitive(tc, "function");
                const char *name = fn ? jstr_get(fn, "name") : NULL;
                const char *args_json = fn ? jstr_get(fn, "arguments") : NULL;

                char result[16384];
                result[0] = 0;

                const ToolDef *td = tools_find(name ? name : "");
                cJSON *args = args_json ? cJSON_Parse(args_json) : cJSON_CreateObject();

                if (!td) {
                    snprintf(result, sizeof(result), "{\"error\":\"unknown tool %s\"}", name ? name : "");
                } else {
                    RiskLevel risk = td->risk_of ? td->risk_of(args) : td->risk;
                    int approved = 1;
                    if (risk_requires_confirm(risk)) {
                        char summary[512];
                        snprintf(summary, sizeof(summary), "Agent 请求调用工具 %s", td->name);
                        Confirmation cf;
                        risk_request(risk, summary, args_json ? args_json : "{}", cfg->confirm_timeout_s, &cf);
                        audit_log("agent", td->name, td->name, "pending", summary);
                        approved = wait_confirm(cf.id, cfg->confirm_timeout_s);
                        audit_log("agent", td->name, td->name, approved ? "approved" : "denied", summary);
                    }
                    if (approved) {
                        td->handler(args, &tctx, result, sizeof(result));
                    } else {
                        snprintf(result, sizeof(result), "{\"error\":\"用户拒绝该操作\"}");
                    }
                }
                if (args) cJSON_Delete(args);

                cJSON *tm = cJSON_CreateObject();
                cJSON_AddStringToObject(tm, "role", "tool");
                cJSON_AddStringToObject(tm, "tool_call_id", tc_id ? tc_id : "");
                cJSON_AddStringToObject(tm, "content", result);
                cJSON_AddItemToArray(messages, tm);
            }
            continue;
        }

        /* No tool calls: final assistant text. */
        const char *content = jstr_get(msg, "content");
        if (content) snprintf(answer, sizeof(answer), "%s", content);
        cJSON_Delete(root);
        break;
    }

    snprintf(out, outlen, "%s", answer);
    cJSON_Delete(tools);
    cJSON_Delete(messages);
    zeroize(api_key, sizeof(api_key));
    return rc;
}
