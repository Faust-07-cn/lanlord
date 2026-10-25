#ifndef LANMGR_KEYSTORE_H
#define LANMGR_KEYSTORE_H

#include <stddef.h>

/* Encrypted API-key store, SEPARATE from device credentials (vault.dat).
 * One encrypted key per provider name. Keys are DPAPI-encrypted at rest. */

/* Store (create/update) the API key for a named provider. */
int keystore_store(const char *path, const char *name, const char *api_key);

/* Retrieve the API key into out (caller MUST zeroize). Returns E_OK on success. */
int keystore_get(const char *path, const char *name, char *out, size_t outlen);

int keystore_delete(const char *path, const char *name);

/* List stored provider names; returns count (negative on error). */
int keystore_list(const char *path, char (*names)[64], int max);

#endif
