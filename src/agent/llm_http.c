#include "wincompat.h"
#include "llm_http.h"
#include "util.h"
#include "error.h"
#include "log.h"
#include <winhttp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Convert UTF-8 to a malloc'd wide string (caller frees). */
static WCHAR *w_from_utf8(const char *s) {
    if (!s) s = "";
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    WCHAR *w = (WCHAR *)malloc((size_t)n * sizeof(WCHAR));
    if (!w) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

/* Parse "https://host[:port][/path]" into components. Returns 0 ok. */
static int parse_url(const char *url, BOOL *https, char *host, size_t hostlen,
                     INTERNET_PORT *port, char *path, size_t pathlen) {
    const char *p = url;
    if (strncmp(p, "https://", 8) == 0) { *https = TRUE;  *port = INTERNET_DEFAULT_HTTPS_PORT; p += 8; }
    else if (strncmp(p, "http://", 7) == 0) { *https = FALSE; *port = INTERNET_DEFAULT_HTTP_PORT; p += 7; }
    else return E_ARG;

    const char *slash = strchr(p, '/');
    const char *endofhost = slash ? slash : (p + strlen(p));

    const char *colon = NULL;
    for (const char *q = p; q < endofhost; q++) if (*q == ':') { colon = q; break; }

    size_t hlen = (colon ? (size_t)(colon - p) : (size_t)(endofhost - p));
    if (hlen == 0 || hlen >= hostlen) return E_ARG;
    memcpy(host, p, hlen); host[hlen] = 0;

    if (colon) {
        const char *ps = colon + 1;
        size_t plen = (size_t)(endofhost - ps);
        char pbuf[16];
        if (plen == 0 || plen >= sizeof(pbuf)) return E_ARG;
        memcpy(pbuf, ps, plen); pbuf[plen] = 0;
        *port = (INTERNET_PORT)atoi(pbuf);
    }

    snprintf(path, pathlen, "%s", slash ? slash : "/");
    return E_OK;
}

/* Read the entire response body into a malloc'd buffer. */
static char *winhttp_read_all(HINTERNET hRequest) {
    size_t cap = 16384, n = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;

    DWORD avail = 0, read = 0;
    for (;;) {
        avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
        if (avail == 0) break;
        while (n + avail + 1 > cap) cap *= 2;
        char *tmp = (char *)realloc(buf, cap);
        if (!tmp) { free(buf); return NULL; }
        buf = tmp;
        read = 0;
        if (!WinHttpReadData(hRequest, buf + n, avail, &read)) break;
        n += read;
    }
    buf[n] = 0;
    return buf;
}

char *llm_chat(const char *full_url, const char *api_key, const char *model,
               cJSON *request_json, int timeout_s) {
    if (!full_url || !api_key || !model || !request_json) return NULL;
    if (timeout_s <= 0) timeout_s = 60;

    BOOL https = FALSE;
    char host[256];
    INTERNET_PORT port = 0;
    char path[512];
    if (parse_url(full_url, &https, host, sizeof(host), &port, path, sizeof(path)) != E_OK) {
        LOGE("invalid agent URL: %s", full_url);
        return NULL;
    }

    char *body = cJSON_PrintUnformatted(request_json);
    if (!body) return NULL;

    char *result = NULL;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    WCHAR *whost = NULL, *wpath = NULL, *wheaders = NULL;

    hSession = WinHttpOpen(L"lanmgr/0.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) goto done;
    WinHttpSetTimeouts(hSession, 10000, 10000, 30000, (int)timeout_s * 1000);

    whost = w_from_utf8(host);
    wpath = w_from_utf8(path);
    if (!whost || !wpath) goto done;

    hConnect = WinHttpConnect(hSession, whost, port, 0);
    if (!hConnect) goto done;

    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    hRequest = WinHttpOpenRequest(hConnect, L"POST", wpath, NULL, NULL, NULL, flags);
    if (!hRequest) goto done;

    char hdr[600];
    snprintf(hdr, sizeof(hdr), "Content-Type: application/json\r\nAuthorization: Bearer %s", api_key);
    wheaders = w_from_utf8(hdr);
    if (!wheaders) goto done;
    WinHttpAddRequestHeaders(hRequest, wheaders, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            (LPVOID)body, (DWORD)strlen(body), (DWORD)strlen(body), 0)) {
        LOGE("WinHttpSendRequest failed (err=%lu)", GetLastError());
        goto done;
    }
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        LOGE("WinHttpReceiveResponse failed (err=%lu)", GetLastError());
        goto done;
    }
    result = winhttp_read_all(hRequest);

done:
    if (wheaders) free(wheaders);
    if (wpath) free(wpath);
    if (whost) free(whost);
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    free(body);
    return result;
}

char *llm_http_get(const char *full_url, const char *api_key, int timeout_s) {
    if (!full_url) return NULL;
    if (timeout_s <= 0) timeout_s = 60;

    BOOL https = FALSE;
    char host[256];
    INTERNET_PORT port = 0;
    char path[512];
    if (parse_url(full_url, &https, host, sizeof(host), &port, path, sizeof(path)) != E_OK)
        return NULL;

    char *result = NULL;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    WCHAR *whost = NULL, *wpath = NULL, *wheaders = NULL;

    hSession = WinHttpOpen(L"lanmgr/0.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) goto done;
    WinHttpSetTimeouts(hSession, 10000, 10000, 30000, (int)timeout_s * 1000);
    whost = w_from_utf8(host);
    wpath = w_from_utf8(path);
    if (!whost || !wpath) goto done;
    hConnect = WinHttpConnect(hSession, whost, port, 0);
    if (!hConnect) goto done;
    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    hRequest = WinHttpOpenRequest(hConnect, L"GET", wpath, NULL, NULL, NULL, flags);
    if (!hRequest) goto done;

    char hdr[600];
    snprintf(hdr, sizeof(hdr), "Authorization: Bearer %s", api_key ? api_key : "");
    wheaders = w_from_utf8(hdr);
    if (!wheaders) goto done;
    WinHttpAddRequestHeaders(hRequest, wheaders, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) goto done;
    if (!WinHttpReceiveResponse(hRequest, NULL)) goto done;
    result = winhttp_read_all(hRequest);

done:
    if (wheaders) free(wheaders);
    if (wpath) free(wpath);
    if (whost) free(whost);
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return result;
}
