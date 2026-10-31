#include "wincompat.h"
#include "vendors.h"
#include "llm_http.h"
#include "util.h"
#include "log.h"
#include "cJSON.h"
#include <string.h>

static const VendorPreset VENDORS[] = {
    { "deepseek",    "DeepSeek（深度求索）",       "https://api.deepseek.com",           "/v1/chat/completions",  "https://api.deepseek.com/models",            "deepseek-chat", 0 },
    { "openai",      "OpenAI",                     "https://api.openai.com",             "/v1/chat/completions",  "https://api.openai.com/v1/models",           "gpt-4o-mini", 0 },
    { "moonshot",    "Moonshot（月之暗面 Kimi）",   "https://api.moonshot.cn",            "/v1/chat/completions",  "https://api.moonshot.cn/v1/models",          "moonshot-v1-8k", 0 },
    { "ark",         "火山方舟 ARK（豆包）",        "https://ark.cn-beijing.volces.com",  "/api/v3/chat/completions","https://ark.cn-beijing.volces.com/api/v3/models", "", 0 },
    { "openrouter",  "OpenRouter",                 "https://openrouter.ai/api",          "/v1/chat/completions",  "https://openrouter.ai/api/v1/models",        "", 0 },
    { "groq",        "Groq",                       "https://api.groq.com/openai",        "/v1/chat/completions",  "https://api.groq.com/openai/v1/models",      "", 0 },
    { "siliconflow", "SiliconFlow（硅基流动）",     "https://api.siliconflow.cn",         "/v1/chat/completions",  "https://api.siliconflow.cn/v1/models",       "deepseek-ai/DeepSeek-V3", 0 },
    { "ollama",      "Ollama（本地）",              "http://localhost:11434",             "/v1/chat/completions",  "http://localhost:11434/api/tags",           "qwen2.5:0.5b-instruct", 1 },
    { "llamacpp",    "llama.cpp（本地 GGUF）",      "http://localhost:8000",              "/v1/chat/completions",  "http://localhost:8000/v1/models",           "qwen2.5-0.5b-instruct", 1 },
};

int vendors_count(void) { return (int)(sizeof(VENDORS) / sizeof(VENDORS[0])); }

const VendorPreset *vendors_at(int i) {
    return (i >= 0 && i < vendors_count()) ? &VENDORS[i] : NULL;
}

const VendorPreset *vendors_find(const char *name) {
    for (int i = 0; i < vendors_count(); i++) if (!strcmp(VENDORS[i].name, name)) return &VENDORS[i];
    return NULL;
}

char *vendor_models_fetch(const char *models_url, const char *api_key, int timeout_s) {
    if (!models_url || !models_url[0]) return NULL;

    char *body = llm_http_get(models_url, api_key, timeout_s);
    if (!body) { LOGW("模型列表请求失败: %s", models_url); return NULL; }

    cJSON *root = cJSON_Parse(body);
    free(body);
    if (!root) return NULL;

    /* provider error (e.g. 401 invalid key) */
    if (cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(root, "error"))) {
        cJSON_Delete(root);
        return NULL;
    }

    cJSON *out = cJSON_CreateArray();

    /* OpenAI-compatible: {"data":[{"id":"..."}]} */
    cJSON *data = cJSON_GetObjectItemCaseSensitive(root, "data");
    if (cJSON_IsArray(data)) {
        int n = cJSON_GetArraySize(data);
        for (int i = 0; i < n; i++) {
            cJSON *m = cJSON_GetArrayItem(data, i);
            cJSON *id = cJSON_GetObjectItemCaseSensitive(m, "id");
            if (cJSON_IsString(id)) cJSON_AddItemToArray(out, cJSON_CreateString(id->valuestring));
        }
    }

    /* Ollama: {"models":[{"name":"..."}]} */
    cJSON *models = cJSON_GetObjectItemCaseSensitive(root, "models");
    if (cJSON_IsArray(models)) {
        int n = cJSON_GetArraySize(models);
        for (int i = 0; i < n; i++) {
            cJSON *m = cJSON_GetArrayItem(models, i);
            cJSON *id = cJSON_GetObjectItemCaseSensitive(m, "name");
            if (!cJSON_IsString(id)) id = cJSON_GetObjectItemCaseSensitive(m, "id");
            if (cJSON_IsString(id)) cJSON_AddItemToArray(out, cJSON_CreateString(id->valuestring));
        }
    }

    cJSON_Delete(root);
    char *s = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    return s; /* "[]" if none matched */
}
