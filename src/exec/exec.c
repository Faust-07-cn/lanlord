#include "wincompat.h"
#include "exec.h"
#include "util.h"
#include "error.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define SSH_PATH "C:\\Windows\\System32\\OpenSSH\\ssh.exe"

/* ---------- primitive: spawn a process, feed stdin, capture stdout+stderr ---------- */

static int read_until_eof(HANDLE h, char **buf, size_t *cap, size_t *len, int timeout_ms) {
    char tmp[8192];
    DWORD avail = 0, left = 0;
    int64_t start = now_ms();
    for (;;) {
        if (!PeekNamedPipe(h, NULL, 0, NULL, &avail, &left)) {
            if (GetLastError() == ERROR_BROKEN_PIPE) break;
            /* h may be a file; fall back to a blocking ReadFile */
            DWORD r = 0;
            if (ReadFile(h, tmp, sizeof(tmp), &r, NULL) && r > 0) {
                if (*len + r > *cap) { *cap = (*len + r) * 2; *buf = (char *)realloc(*buf, *cap); }
                memcpy(*buf + *len, tmp, r); *len += r;
                continue;
            }
            break;
        }
        if (avail > 0) {
            DWORD r = 0;
            if (ReadFile(h, tmp, sizeof(tmp), &r, NULL) && r > 0) {
                if (*len + r > *cap) { *cap = (*len + r) * 2 + 8; *buf = (char *)realloc(*buf, *cap); }
                memcpy(*buf + *len, tmp, r); *len += r;
                continue;
            }
        }
        if (timeout_ms > 0 && now_ms() - start > timeout_ms) break;
        Sleep(20);
    }
    return 0;
}

static int spawn_capture(const char *cmdline, const char *stdin_data, char *out, size_t outlen, int timeout_ms) {
    if (outlen) out[0] = 0;

    SECURITY_ATTRIBUTES sa; sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE; sa.lpSecurityDescriptor = NULL;
    HANDLE hOutR = NULL, hOutW = NULL, hInR = NULL, hInW = NULL;
    if (!CreatePipe(&hOutR, &hOutW, &sa, 0)) return E_IO;
    if (!CreatePipe(&hInR, &hInW, &sa, 0)) { CloseHandle(hOutR); CloseHandle(hOutW); return E_IO; }
    SetHandleInformation(hOutR, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hInW, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si; memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = hInR;
    si.hStdOutput = hOutW;
    si.hStdError = hOutW; /* merge stderr into stdout */

    PROCESS_INFORMATION pi; memset(&pi, 0, sizeof(pi));
    /* cmdline is a mutable buffer requirement for CreateProcessA */
    char *cmd = lstrdup(cmdline);
    if (!cmd) return E_NOMEM;

    BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    free(cmd);
    if (!ok) { CloseHandle(hOutR); CloseHandle(hOutW); CloseHandle(hInR); CloseHandle(hInW); return E_IO; }

    CloseHandle(hOutW); /* parent doesn't write stdout */
    CloseHandle(hInR);  /* parent doesn't read stdin */

    /* feed stdin (e.g. sudo password) */
    if (stdin_data && stdin_data[0]) {
        DWORD wr = 0;
        WriteFile(hInW, stdin_data, (DWORD)strlen(stdin_data), &wr, NULL);
    }
    CloseHandle(hInW);

    char *buf = (char *)calloc(1, 8192);
    size_t cap = 8192, len = 0;
    read_until_eof(hOutR, &buf, &cap, &len, timeout_ms);

    CloseHandle(hOutR);
    WaitForSingleObject(pi.hProcess, 2000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (len >= outlen) len = outlen - 1;
    memcpy(out, buf, len);
    out[len] = 0;
    free(buf);
    return E_OK;
}

/* ---------- local exec ---------- */

int exec_local_run(const char *command, const ExecOpts *opts, char *out, size_t outlen) {
    char cmdline[4096];
    if (opts && opts->escalate) {
        /* Windows 11 24H2 ships sudo.exe; try it, else fall back with an error. */
        snprintf(cmdline, sizeof(cmdline), "sudo.exe %s", command ? command : "");
    } else {
        snprintf(cmdline, sizeof(cmdline), "cmd.exe /c %s", command ? command : "");
    }
    int to = (opts && opts->timeout_s > 0) ? opts->timeout_s * 1000 : 20000;
    return spawn_capture(cmdline, NULL, out, outlen, to);
}

/* ---------- ssh ---------- */

bool ssh_available(void) {
    DWORD a = GetFileAttributesA(SSH_PATH);
    return a != INVALID_FILE_ATTRIBUTES;
}

static void setenv_tmp(const char *k, const char *v) { SetEnvironmentVariableA(k, v); }

/* Escape a string for inclusion in a POSIX sh -c '...' single-quoted context.
 * Single quotes inside the command are replaced by '\'' (close, quote, reopen). */
static void sh_squote(const char *s, char *out, size_t n) {
    size_t j = 0;
    if (j + 1 < n) out[j++] = '\'';
    for (const char *p = s; p && *p; p++) {
        if (*p == '\'') {
            if (j + 4 < n) { out[j++]='\''; out[j++]='\\'; out[j++]='\''; out[j++]='\''; }
        } else if (j + 1 < n) out[j++] = *p;
    }
    if (j + 1 < n) out[j++] = '\'';
    out[j] = 0;
}

int exec_remote_run(Vault *v, const char *ip, const char *cred_id, const char *command,
                    const ExecOpts *opts, char *out, size_t outlen) {
    if (!ssh_available()) {
        snprintf(out, outlen, "未找到系统 SSH 客户端(%s)，请启用 OpenSSH.Client", SSH_PATH);
        return E_UNSUPPORTED;
    }
    if (!v || !ip || !cred_id || !command) return E_ARG;

    CredPlain cred; memset(&cred, 0, sizeof(cred));
    if (vault_get(v, cred_id, &cred) != E_OK) {
        snprintf(out, outlen, "凭据 %s 不存在", cred_id);
        return E_NOTFOUND;
    }
    log_redact(cred.secret);
    log_redact(cred.username);

    /* Build remote command (with optional sudo escalation). */
    char remote[8192];
    char esc[4200];
    if (opts && opts->escalate) {
        sh_squote(command, esc, sizeof(esc));
        snprintf(remote, sizeof(remote), "sudo -S -p '' -- sh -c %s", esc);
    } else {
        snprintf(remote, sizeof(remote), "%s", command);
    }

    /* Assemble ssh command line (remote command is one double-quoted arg). */
    char cmdline[16384];
    snprintf(cmdline, sizeof(cmdline),
             "\"%s\" -o BatchMode=no -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "
             "-o PreferredAuthentications=password -o PubkeyAuthentication=no -T %s@%s \"%s\"",
             SSH_PATH, cred.username, ip, remote);

    /* Askpass: our own exe in --askpass mode reads the password from the env. */
    char exepath[MAX_PATH];
    GetModuleFileNameA(NULL, exepath, sizeof(exepath));
    char askpass[560];
    snprintf(askpass, sizeof(askpass), "\"%s\" --askpass", exepath);

    setenv_tmp("LANMGR_ASKPASS_PW", cred.secret);
    setenv_tmp("SSH_ASKPASS", askpass);
    setenv_tmp("SSH_ASKPASS_REQUIRE", "force");
    setenv_tmp("DISPLAY", "localhost:0");

    int to = (opts && opts->timeout_s > 0) ? opts->timeout_s * 1000 : 20000;
    /* sudo reads password from stdin (only when escalating). */
    char sudopw[520];
    const char *stdin_data = NULL;
    if (opts && opts->escalate) {
        snprintf(sudopw, sizeof(sudopw), "%s\n", cred.secret);
        stdin_data = sudopw;
    }
    int rc = spawn_capture(cmdline, stdin_data, out, outlen, to);

    /* clear env now that the child is done */
    SetEnvironmentVariableA("LANMGR_ASKPASS_PW", NULL);
    SetEnvironmentVariableA("SSH_ASKPASS", NULL);
    SetEnvironmentVariableA("SSH_ASKPASS_REQUIRE", NULL);
    SetEnvironmentVariableA("DISPLAY", NULL);
    zeroize(sudopw, sizeof(sudopw));
    cred_zeroize(&cred);
    return rc;
}
