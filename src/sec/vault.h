#ifndef LANMGR_VAULT_H
#define LANMGR_VAULT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum { CRED_SSH = 0, CRED_WINRM = 1, CRED_HTTP = 2, CRED_APITOKEN = 3 } CredType;

#define CRED_FLAG_PLAINTEXT 0x1u   /* store secret unencrypted (requires permit_plaintext) */

/* A credential as used in memory. username/secret hold transient plaintext ONLY;
 * callers MUST zeroize via cred_zeroize() after use. */
typedef struct {
    char     id[40];
    CredType type;
    uint32_t flags;
    char     label[128];
    char     target[256];
    char     username[128];
    char     secret[512];
    char     notes[256];
} CredPlain;

typedef struct {
    char path[512];
    bool permit_plaintext;
} Vault;

void vault_init(Vault *v, const char *path, bool permit_plaintext);

/* Zeroize the transient secret material in a credential. */
void cred_zeroize(CredPlain *c);

/* Store (create/update) a credential. Secrets are encrypted via DPAPI unless the
 * caller explicitly requests plaintext AND the vault permits it. */
int vault_store(Vault *v, const CredPlain *c);

/* List credentials WITHOUT secret material (username/secret left empty). */
int vault_list(Vault *v, CredPlain *out, int max);

/* Retrieve a credential by id, filling username/secret (caller MUST zeroize). */
int vault_get(Vault *v, const char *id, CredPlain *out);

int vault_delete(Vault *v, const char *id);

const char *cred_type_str(CredType t);

#endif
