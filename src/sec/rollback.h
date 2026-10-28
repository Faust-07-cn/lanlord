#ifndef LANMGR_ROLLBACK_H
#define LANMGR_ROLLBACK_H

#include <stdint.h>
#include <stddef.h>

/* Persistent journal of reversible risky operations executed by the Agent.
 * Each entry records enough context to undo the operation on demand.
 * Backed by a JSON-lines file (rollback.log); loaded into memory at init. */

enum { ROLLBACK_APPLIED = 0, ROLLBACK_ROLLED_BACK = 1, ROLLBACK_FAILED = 2 };

typedef struct {
    char     id[40];
    int64_t  created_ms;
    char     kind[40];         /* forward op: "exec.local" | "exec.remote" | "credential.add" */
    char     target[256];      /* "local" / ip / credential label */
    char     summary[512];     /* forward command (redacted) for display */
    char     mode[16];         /* how it was authorized: "semi" | "full" */

    /* rollback plan */
    char     rkind[40];        /* "exec.local" | "exec.remote" | "credential.delete" */
    char     rcmd[4096];       /* reverse command (exec.*) */
    char     rip[64];          /* remote rollback host (exec.remote) */
    char     rcred[64];        /* remote rollback credential id (exec.remote) */
    int      resc;             /* remote rollback escalate flag */
    char     cred_id[64];      /* credential id to delete (credential.delete) */

    int      status;           /* ROLLBACK_* */
    int64_t  rolled_ms;
} RollbackEntry;

int rollback_init(const char *path);

/* Record an APPLIED entry; assigns id, appends to memory + file. */
int rollback_record(const RollbackEntry *e, char *out_id, size_t out_id_len);

/* Fill up to max entries, most recent first. Returns count. */
int rollback_list(RollbackEntry *out, int max);

/* Number of entries still APPLIED (available to roll back). */
int rollback_applied_count(void);

int rollback_get(const char *id, RollbackEntry *out);

/* Update status (rolled_back / failed); rewrites the backing file. */
int rollback_mark(const char *id, int status);

#endif