#ifndef LANMGR_LLM_HTTP_H
#define LANMGR_LLM_HTTP_H

#include "cJSON.h"

/* POST the JSON request to full_url (scheme://host[:port]/path, already the complete
 * OpenAI-compatible endpoint) over HTTPS via WinHTTP. Returns malloc'd response body
 * string (JSON), or NULL on failure. */
char *llm_chat(const char *full_url, const char *api_key, const char *model,
               cJSON *request_json, int timeout_s);

#endif
