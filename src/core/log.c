#include "wincompat.h"
#include "log.h"
#include "util.h"
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static FILE *g_fp = NULL;
static LogLevel g_level = LOG_INFO;
static CRITICAL_SECTION g_lock;
static int g_inited = 0;

#define MAX_REDACT 32
static char *g_redact[MAX_REDACT];
static int g_nredact = 0;

static const char *level_name(LogLevel l) {
    switch (l) {
        case LOG_TRACE: return "TRACE";
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO:  return "INFO ";
        case LOG_WARN:  return "WARN ";
        case LOG_ERROR: return "ERROR";
    }
    return "?????";
}

void log_init(const char *path, LogLevel level) {
    if (g_inited) return;
    InitializeCriticalSection(&g_lock);
    g_level = level;
    if (path && path[0]) g_fp = fopen(path, "a");
    g_inited = 1;
}

void log_set_level(LogLevel level) { g_level = level; }

void log_redact(const char *secret) {
    if (!secret || !secret[0]) return;
    EnterCriticalSection(&g_lock);
    if (g_nredact < MAX_REDACT) g_redact[g_nredact++] = lstrdup(secret);
    LeaveCriticalSection(&g_lock);
}

static char *apply_redact(char *msg) {
    for (int i = 0; i < g_nredact; i++) {
        const char *s = g_redact[i];
        if (!s || !s[0]) continue;
        size_t slen = strlen(s);
        char *p = msg;
        while ((p = strstr(p, s)) != NULL) {
            for (size_t k = 0; k < slen; k++) p[k] = '*';
            p += slen;
        }
    }
    return msg;
}

void log_close(void) {
    EnterCriticalSection(&g_lock);
    if (g_fp) { fclose(g_fp); g_fp = NULL; }
    LeaveCriticalSection(&g_lock);
}

void log_msg(LogLevel lvl, const char *fmt, ...) {
    if (lvl < g_level) return;
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    apply_redact(buf);

    SYSTEMTIME st;
    GetLocalTime(&st);
    char line[4600];
    snprintf(line, sizeof(line), "%04d-%02d-%02d %02d:%02d:%02d.%03d [%s] %s\n",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
             level_name(lvl), buf);

    EnterCriticalSection(&g_lock);
    if (g_fp) { fputs(line, g_fp); fflush(g_fp); }
    fputs(line, stderr);
    LeaveCriticalSection(&g_lock);
}
