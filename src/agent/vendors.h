#ifndef LANMGR_VENDORS_H
#define LANMGR_VENDORS_H

/* Preset catalog of OpenAI-compatible AI providers (CC-Switch style).
 * Selecting a vendor auto-fills call address (base_url) + request path (endpoint). */
typedef struct {
    const char *name;          /* short id, also used as provider name */
    const char *label;         /* display name */
    const char *base_url;      /* 调用地址 */
    const char *endpoint;      /* 请求地址 (chat/completions path) */
    const char *models_url;    /* 模型列表地址 (may be empty) */
    const char *default_model; /* 默认模型 (may be empty) */
} VendorPreset;

int vendors_count(void);
const VendorPreset *vendors_at(int i);
const VendorPreset *vendors_find(const char *name);

/* Fetch the model list via GET models_url (Bearer api_key). Returns a malloc'd JSON
 * array of model-id strings on success, or NULL on failure (bad key/url/format). */
char *vendor_models_fetch(const char *models_url, const char *api_key, int timeout_s);

#endif
