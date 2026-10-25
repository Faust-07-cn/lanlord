#include "wincompat.h"
#include "keystore.h"
#include "util.h"
#include "error.h"
#include "log.h"
#include <wincrypt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define KSTORE_MAGIC "LANKYST1"
#define KSTORE_VERSION 1u
#define KSTORE_MAX 64

typedef struct {
    char name[64];
    uint8_t *blob; uint32_t blob_len;
} KeyEntry;

/* ---------- DPAPI (local copies; encrypted at rest) ---------- */

static uint8_t *dpapi_protect(const char *plain, uint32_t *outlen) {
    DATA_BLOB in, out;
    in.pbData = (BYTE *)(void *)plain;
    in.cbData = (DWORD)strlen(plain);
    out.pbData = NULL; out.cbData = 0;
    DWORD flags = CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN;
    if (!CryptProtectData(&in, L"lanmgr-apikey", NULL, NULL, NULL, flags, &out)) {
        flags = CRYPTPROTECT_UI_FORBIDDEN;
        if (!CryptProtectData(&in, L"lanmgr-apikey", NULL, NULL, NULL, flags, &out)) return NULL;
    }
    uint8_t *r = (uint8_t *)malloc(out.cbData + 1);
    if (r) { memcpy(r, out.pbData, out.cbData); r[out.cbData] = 0; *outlen = out.cbData; }
    zeroize(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return r;
}

static char *dpapi_unprotect(const uint8_t *blob, uint32_t len) {
    DATA_BLOB in, out;
    in.pbData = (BYTE *)(void *)blob;
    in.cbData = (DWORD)len;
    out.pbData = NULL; out.cbData = 0;
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &out)) return NULL;
    char *r = (char *)malloc(out.cbData + 1);
    if (r) { memcpy(r, out.pbData, out.cbData); r[out.cbData] = 0; }
    zeroize(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return r;
}

static int read_all(const char *path, KeyEntry **out, int *n) {
    *out = NULL; *n = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return E_NOTFOUND;
    char magic[8] = {0}; uint32_t ver = 0, count = 0;
    int ok = 1;
    if (fread(magic, 1, 8, f) != 8 || memcmp(magic, KSTORE_MAGIC, 8) != 0) ok = 0;
    if (ok && (fread(&ver, 4, 1, f) != 1 || ver != KSTORE_VERSION)) ok = 0;
    if (ok && fread(&count, 4, 1, f) != 1) ok = 0;
    if (ok && count > KSTORE_MAX) ok = 0;
    if (!ok) { fclose(f); return E_IO; }

    KeyEntry *arr = (KeyEntry *)calloc(count ? count : 1, sizeof(KeyEntry));
    if (!arr) { fclose(f); return E_NOMEM; }
    for (uint32_t i = 0; i < count; i++) {
        KeyEntry *e = &arr[i];
        if (fread(e->name, 1, 64, f) != 64) goto fail;
        if (fread(&e->blob_len, 4, 1, f) != 1) goto fail;
        if (e->blob_len > (1u << 20)) goto fail;
        if (e->blob_len) {
            e->blob = (uint8_t *)malloc(e->blob_len);
            if (!e->blob || fread(e->blob, 1, e->blob_len, f) != e->blob_len) goto fail;
        }
    }
    fclose(f);
    *out = arr; *n = (int)count;
    return E_OK;
fail:
    fclose(f);
    for (uint32_t i = 0; i < count; i++) free(arr[i].blob);
    free(arr);
    return E_IO;
}

static void free_all(KeyEntry *e, int n) {
    if (!e) return;
    for (int i = 0; i < n; i++) free(e[i].blob);
    free(e);
}

static int write_all(const char *path, KeyEntry *e, int n) {
    FILE *f = fopen(path, "wb");
    if (!f) return E_IO;
    fwrite(KSTORE_MAGIC, 1, 8, f);
    uint32_t ver = KSTORE_VERSION; fwrite(&ver, 4, 1, f);
    uint32_t count = (uint32_t)n; fwrite(&count, 4, 1, f);
    for (int i = 0; i < n; i++) {
        KeyEntry *x = &e[i];
        fwrite(x->name, 1, 64, f);
        fwrite(&x->blob_len, 4, 1, f);
        if (x->blob_len) fwrite(x->blob, 1, x->blob_len, f);
    }
    fclose(f);
    return E_OK;
}

int keystore_store(const char *path, const char *name, const char *api_key) {
    if (!path || !name || !api_key) return E_ARG;
    KeyEntry *arr = NULL; int n = 0;
    int rc = read_all(path, &arr, &n);
    if (rc == E_IO) return E_IO;
    if (rc == E_NOTFOUND) { arr = NULL; n = 0; }

    int idx = -1;
    for (int i = 0; i < n; i++) if (strcmp(arr[i].name, name) == 0) { idx = i; break; }
    if (idx < 0) {
        arr = (KeyEntry *)realloc(arr, (size_t)(n + 1) * sizeof(KeyEntry));
        memset(&arr[n], 0, sizeof(KeyEntry));
        idx = n; n++;
        snprintf(arr[idx].name, sizeof(arr[idx].name), "%s", name);
    }
    KeyEntry *e = &arr[idx];
    free(e->blob); e->blob = NULL; e->blob_len = 0;
    e->blob = dpapi_protect(api_key, &e->blob_len);
    if (!e->blob) { free_all(arr, n); return E_INTERNAL; }

    rc = write_all(path, arr, n);
    free_all(arr, n);
    return rc;
}

int keystore_get(const char *path, const char *name, char *out, size_t outlen) {
    if (out && outlen) out[0] = 0;
    KeyEntry *arr = NULL; int n = 0;
    int rc = read_all(path, &arr, &n);
    if (rc != E_OK) return rc;

    int rc2 = E_NOTFOUND;
    for (int i = 0; i < n; i++) {
        if (strcmp(arr[i].name, name) == 0) {
            if (arr[i].blob_len) {
                char *p = dpapi_unprotect(arr[i].blob, arr[i].blob_len);
                if (p) { snprintf(out, outlen, "%s", p); zeroize(p, strlen(p)); free(p); rc2 = E_OK; }
                else rc2 = E_IO;
            }
            break;
        }
    }
    free_all(arr, n);
    return rc2;
}

int keystore_delete(const char *path, const char *name) {
    KeyEntry *arr = NULL; int n = 0;
    int rc = read_all(path, &arr, &n);
    if (rc != E_OK) return rc;
    int idx = -1;
    for (int i = 0; i < n; i++) if (strcmp(arr[i].name, name) == 0) { idx = i; break; }
    if (idx < 0) { free_all(arr, n); return E_NOTFOUND; }
    free(arr[idx].blob); arr[idx].blob = NULL;
    for (int i = idx; i < n - 1; i++) arr[i] = arr[i + 1];
    n--;
    rc = write_all(path, arr, n);
    free_all(arr, n);
    return rc;
}

int keystore_list(const char *path, char (*names)[64], int max) {
    KeyEntry *arr = NULL; int n = 0;
    int rc = read_all(path, &arr, &n);
    if (rc == E_NOTFOUND) return 0;
    if (rc != E_OK) return rc;
    int k = 0;
    for (int i = 0; i < n && k < max; i++) {
        snprintf(names[k], 64, "%s", arr[i].name);
        k++;
    }
    free_all(arr, n);
    return k;
}
