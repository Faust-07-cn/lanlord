#include "wincompat.h"
#include "vault.h"
#include "util.h"
#include "error.h"
#include "log.h"
#include <wincrypt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define VAULT_MAGIC "LANMVLT1"
#define VAULT_VERSION 1u

typedef struct {
    char     id[40];
    uint32_t type;
    uint32_t flags;
    char     label[128];
    char     target[256];
    char     notes[256];
    uint8_t *user;   uint32_t user_len;    /* at-rest blob (encrypted or plaintext) */
    uint8_t *secret; uint32_t secret_len;
} VEntry;

void vault_init(Vault *v, const char *path, bool permit_plaintext) {
    memset(v, 0, sizeof(*v));
    snprintf(v->path, sizeof(v->path), "%s", path ? path : "vault.dat");
    v->permit_plaintext = permit_plaintext;
}

void cred_zeroize(CredPlain *c) {
    if (!c) return;
    zeroize(c->username, sizeof(c->username));
    zeroize(c->secret, sizeof(c->secret));
}

const char *cred_type_str(CredType t) {
    switch (t) {
        case CRED_SSH: return "ssh";
        case CRED_WINRM: return "winrm";
        case CRED_HTTP: return "http";
        case CRED_APITOKEN: return "apitoken";
        default: return "unknown";
    }
}

/* ---------- DPAPI ---------- */

static uint8_t *dpapi_protect(const char *plain, uint32_t *outlen) {
    DATA_BLOB in, out;
    in.pbData = (BYTE *)(void *)plain;
    in.cbData = (DWORD)strlen(plain);
    out.pbData = NULL; out.cbData = 0;

    DWORD flags = CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN;
    if (!CryptProtectData(&in, L"lanmgr-vault", NULL, NULL, NULL, flags, &out)) {
        flags = CRYPTPROTECT_UI_FORBIDDEN; /* fall back to per-user scope */
        if (!CryptProtectData(&in, L"lanmgr-vault", NULL, NULL, NULL, flags, &out))
            return NULL;
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
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &out))
        return NULL;
    char *r = (char *)malloc(out.cbData + 1);
    if (r) { memcpy(r, out.pbData, out.cbData); r[out.cbData] = 0; }
    zeroize(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return r;
}

/* ---------- (de)serialization ---------- */

static int read_entries(Vault *v, VEntry **out, int *n) {
    *out = NULL; *n = 0;
    FILE *f = fopen(v->path, "rb");
    if (!f) return E_NOTFOUND;

    char magic[8] = {0};
    uint32_t ver = 0, count = 0;
    int ok = 1;
    if (fread(magic, 1, 8, f) != 8 || memcmp(magic, VAULT_MAGIC, 8) != 0) ok = 0;
    if (ok && (fread(&ver, 4, 1, f) != 1 || ver != VAULT_VERSION)) ok = 0;
    if (ok && fread(&count, 4, 1, f) != 1) ok = 0;
    if (ok && count > 4096) ok = 0;
    if (!ok) { fclose(f); return E_IO; }

    VEntry *arr = (VEntry *)calloc(count ? count : 1, sizeof(VEntry));
    if (!arr) { fclose(f); return E_NOMEM; }

    for (uint32_t i = 0; i < count; i++) {
        VEntry *e = &arr[i];
        if (fread(e->id, 1, 40, f) != 40) goto fail;
        if (fread(&e->type, 4, 1, f) != 1) goto fail;
        if (fread(&e->flags, 4, 1, f) != 1) goto fail;
        if (fread(e->label, 1, 128, f) != 128) goto fail;
        if (fread(e->target, 1, 256, f) != 256) goto fail;
        if (fread(e->notes, 1, 256, f) != 256) goto fail;
        if (fread(&e->user_len, 4, 1, f) != 1) goto fail;
        if (e->user_len > (1u << 20)) goto fail;
        if (e->user_len) {
            e->user = (uint8_t *)malloc(e->user_len);
            if (!e->user || fread(e->user, 1, e->user_len, f) != e->user_len) goto fail;
        }
        if (fread(&e->secret_len, 4, 1, f) != 1) goto fail;
        if (e->secret_len > (1u << 20)) goto fail;
        if (e->secret_len) {
            e->secret = (uint8_t *)malloc(e->secret_len);
            if (!e->secret || fread(e->secret, 1, e->secret_len, f) != e->secret_len) goto fail;
        }
    }
    fclose(f);
    *out = arr; *n = (int)count;
    return E_OK;

fail:
    fclose(f);
    for (uint32_t i = 0; i < count; i++) { free(arr[i].user); free(arr[i].secret); }
    free(arr);
    return E_IO;
}

static void free_entries(VEntry *e, int n) {
    if (!e) return;
    for (int i = 0; i < n; i++) { free(e[i].user); free(e[i].secret); }
    free(e);
}

static int write_entries(Vault *v, VEntry *e, int n) {
    FILE *f = fopen(v->path, "wb");
    if (!f) return E_IO;
    fwrite(VAULT_MAGIC, 1, 8, f);
    uint32_t ver = VAULT_VERSION; fwrite(&ver, 4, 1, f);
    uint32_t count = (uint32_t)n; fwrite(&count, 4, 1, f);
    for (int i = 0; i < n; i++) {
        VEntry *x = &e[i];
        fwrite(x->id, 1, 40, f);
        fwrite(&x->type, 4, 1, f);
        fwrite(&x->flags, 4, 1, f);
        fwrite(x->label, 1, 128, f);
        fwrite(x->target, 1, 256, f);
        fwrite(x->notes, 1, 256, f);
        fwrite(&x->user_len, 4, 1, f);
        if (x->user_len) fwrite(x->user, 1, x->user_len, f);
        fwrite(&x->secret_len, 4, 1, f);
        if (x->secret_len) fwrite(x->secret, 1, x->secret_len, f);
    }
    fclose(f);
    return E_OK;
}

/* Encrypt (or plaintext-if-explicitly-permitted) plain into a blob. */
static int blob_from_plain(Vault *v, const char *plain, uint32_t flags, uint8_t **blob, uint32_t *blen) {
    *blob = NULL; *blen = 0;
    if (!plain || !plain[0]) return E_OK; /* empty secret -> empty blob */

    if ((flags & CRED_FLAG_PLAINTEXT) && v->permit_plaintext) {
        size_t n = strlen(plain);
        *blob = (uint8_t *)malloc(n + 1);
        if (!*blob) return E_NOMEM;
        memcpy(*blob, plain, n + 1);
        *blen = (uint32_t)n;
        LOGW("credential stored in PLAINTEXT at explicit user request");
        return E_OK;
    }
    if ((flags & CRED_FLAG_PLAINTEXT) && !v->permit_plaintext) {
        LOGE("plaintext storage requested but not permitted by config; encrypting instead");
    }
    *blob = dpapi_protect(plain, blen);
    return *blob ? E_OK : E_INTERNAL;
}

/* ---------- public API ---------- */

int vault_store(Vault *v, const CredPlain *c) {
    if (!v || !c) return E_ARG;

    VEntry *arr = NULL; int n = 0;
    int rc = read_entries(v, &arr, &n);
    if (rc == E_IO) return E_IO;
    if (rc == E_NOTFOUND) { arr = NULL; n = 0; }

    int idx = -1;
    if (c->id[0]) for (int i = 0; i < n; i++) if (strcmp(arr[i].id, c->id) == 0) { idx = i; break; }

    if (idx < 0) {
        arr = (VEntry *)realloc(arr, (size_t)(n + 1) * sizeof(VEntry));
        if (!arr) return E_NOMEM;
        memset(&arr[n], 0, sizeof(VEntry));
        idx = n;
        n++;
        if (c->id[0]) snprintf(arr[idx].id, 40, "%s", c->id);
        else { char tmp[24]; gen_id(tmp, sizeof(tmp)); snprintf(arr[idx].id, 40, "c-%s", tmp); }
    }

    VEntry *e = &arr[idx];
    /* free old blobs before replacement (and zero pages) */
    free(e->user); e->user = NULL; e->user_len = 0;
    free(e->secret); e->secret = NULL; e->secret_len = 0;

    e->type = (uint32_t)c->type;
    e->flags = c->flags;
    snprintf(e->label, sizeof(e->label), "%s", c->label);
    snprintf(e->target, sizeof(e->target), "%s", c->target);
    snprintf(e->notes, sizeof(e->notes), "%s", c->notes);

    rc = blob_from_plain(v, c->username, c->flags, &e->user, &e->user_len);
    if (rc == E_OK) rc = blob_from_plain(v, c->secret, c->flags, &e->secret, &e->secret_len);
    if (rc != E_OK) { free(e->user); free(e->secret); free_entries(arr, n); return rc; }

    rc = write_entries(v, arr, n);
    free_entries(arr, n);
    return rc;
}

int vault_list(Vault *v, CredPlain *out, int max) {
    VEntry *arr = NULL; int n = 0;
    int rc = read_entries(v, &arr, &n);
    if (rc != E_OK) return rc;

    int k = 0;
    for (int i = 0; i < n && k < max; i++) {
        CredPlain *o = &out[k];
        memset(o, 0, sizeof(*o));
        snprintf(o->id, sizeof(o->id), "%s", arr[i].id);
        o->type = (CredType)arr[i].type;
        o->flags = arr[i].flags;
        snprintf(o->label, sizeof(o->label), "%s", arr[i].label);
        snprintf(o->target, sizeof(o->target), "%s", arr[i].target);
        snprintf(o->notes, sizeof(o->notes), "%s", arr[i].notes);
        k++;
    }
    free_entries(arr, n);
    return k;
}

int vault_get(Vault *v, const char *id, CredPlain *out) {
    VEntry *arr = NULL; int n = 0;
    int rc = read_entries(v, &arr, &n);
    if (rc != E_OK) return rc;

    int rc2 = E_NOTFOUND;
    for (int i = 0; i < n; i++) {
        if (strcmp(arr[i].id, id) == 0) {
            VEntry *e = &arr[i];
            memset(out, 0, sizeof(*out));
            snprintf(out->id, sizeof(out->id), "%s", e->id);
            out->type = (CredType)e->type;
            out->flags = e->flags;
            snprintf(out->label, sizeof(out->label), "%s", e->label);
            snprintf(out->target, sizeof(out->target), "%s", e->target);
            snprintf(out->notes, sizeof(out->notes), "%s", e->notes);

            if (e->flags & CRED_FLAG_PLAINTEXT) {
                snprintf(out->username, sizeof(out->username), "%s", (char *)e->user);
                snprintf(out->secret, sizeof(out->secret), "%s", (char *)e->secret);
            } else {
                if (e->user_len) {
                    char *u = dpapi_unprotect(e->user, e->user_len);
                    if (u) { snprintf(out->username, sizeof(out->username), "%s", u); zeroize(u, strlen(u)); free(u); }
                }
                if (e->secret_len) {
                    char *s = dpapi_unprotect(e->secret, e->secret_len);
                    if (s) { snprintf(out->secret, sizeof(out->secret), "%s", s); zeroize(s, strlen(s)); free(s); }
                }
            }
            rc2 = E_OK;
            break;
        }
    }
    free_entries(arr, n);
    return rc2;
}

int vault_delete(Vault *v, const char *id) {
    VEntry *arr = NULL; int n = 0;
    int rc = read_entries(v, &arr, &n);
    if (rc != E_OK) return rc;

    int idx = -1;
    for (int i = 0; i < n; i++) if (strcmp(arr[i].id, id) == 0) { idx = i; break; }
    if (idx < 0) { free_entries(arr, n); return E_NOTFOUND; }

    free(arr[idx].user); arr[idx].user = NULL;
    free(arr[idx].secret); arr[idx].secret = NULL;
    for (int i = idx; i < n - 1; i++) arr[i] = arr[i + 1];
    n--;

    rc = write_entries(v, arr, n);
    free_entries(arr, n);
    return rc;
}
