#ifndef LANMGR_EXEC_H
#define LANMGR_EXEC_H

#include <stdbool.h>
#include <stddef.h>
#include "sec/vault.h"

typedef struct {
    bool  escalate;   /* sudo -S (Linux) / sudo (Windows) */
    int   timeout_s;  /* 0 = default 20s */
} ExecOpts;

/* Run a command on the manager host; captured stdout+stderr into out. */
int exec_local_run(const char *command, const ExecOpts *opts, char *out, size_t outlen);

/* Run a command on a remote host. Linux targets use system ssh.exe; Windows/winrm is a stub.
 * cred_id names a vault credential (username + password). */
int exec_remote_run(Vault *v, const char *ip, const char *cred_id, const char *command,
                    const ExecOpts *opts, char *out, size_t outlen);

/* Locate the system OpenSSH ssh.exe; returns true if present. */
bool ssh_available(void);

#endif
