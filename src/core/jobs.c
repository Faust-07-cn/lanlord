#include "wincompat.h"
#include "jobs.h"
#include "log.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static CRITICAL_SECTION g_lock;
static Job *g_head = NULL;
static volatile LONG g_next = 0;
static int g_inited = 0;

int jobs_init(void) {
    if (g_inited) return 0;
    InitializeCriticalSection(&g_lock);
    g_inited = 1;
    return 0;
}

static void copy_into(char *dst, size_t n, const char *src) {
    snprintf(dst, n, "%s", src ? src : "");
}

static DWORD WINAPI worker(LPVOID p) {
    Job *job = (Job *)p;

    EnterCriticalSection(&g_lock);
    job->status = 1;
    LeaveCriticalSection(&g_lock);

    char out[8192];
    out[0] = 0;
    int rc = job->run ? job->run(job, out, sizeof(out)) : -1;

    EnterCriticalSection(&g_lock);
    if (rc == 0) { job->status = 2; copy_into(job->result, sizeof(job->result), out); }
    else {
        job->status = 3;
        if (out[0]) copy_into(job->error, sizeof(job->error), out);
        else snprintf(job->error, sizeof(job->error), "rc=%d", rc);
    }
    LeaveCriticalSection(&g_lock);

    if (job->cleanup) job->cleanup(job->ctx);
    return 0;
}

Job *jobs_submit(const char *kind, void *ctx, JobRunFn run, JobCleanupFn cleanup) {
    if (!g_inited) jobs_init();

    Job *j = (Job *)calloc(1, sizeof(Job));
    if (!j) return NULL;
    j->id = (int)InterlockedIncrement(&g_next);
    copy_into(j->kind, sizeof(j->kind), kind);
    j->ctx = ctx;
    j->run = run;
    j->cleanup = cleanup;
    j->status = 0;

    EnterCriticalSection(&g_lock);
    j->next = g_head;
    g_head = j;
    LeaveCriticalSection(&g_lock);

    HANDLE h = CreateThread(NULL, 0, worker, j, 0, NULL);
    if (h) {
        CloseHandle(h);
    } else {
        EnterCriticalSection(&g_lock);
        j->status = 3;
        copy_into(j->error, sizeof(j->error), "thread create failed");
        LeaveCriticalSection(&g_lock);
    }
    return j;
}

Job *jobs_find(int id) {
    Job *r = NULL;
    EnterCriticalSection(&g_lock);
    for (Job *j = g_head; j; j = j->next) {
        if (j->id == id) { r = j; break; }
    }
    LeaveCriticalSection(&g_lock);
    return r;
}

void jobs_progress_set(Job *j, int progress) {
    if (!j) return;
    EnterCriticalSection(&g_lock);
    j->progress = progress;
    LeaveCriticalSection(&g_lock);
}

void jobs_status(const Job *j, int *status, int *progress) {
    if (!j) {
        if (status) *status = 3;
        if (progress) *progress = 0;
        return;
    }
    EnterCriticalSection(&g_lock);
    if (status) *status = j->status;
    if (progress) *progress = j->progress;
    LeaveCriticalSection(&g_lock);
}

const char *jobs_result(const Job *j) {
    static char buf[8192];
    buf[0] = 0;
    if (!j) return buf;
    EnterCriticalSection(&g_lock);
    copy_into(buf, sizeof(buf), j->result);
    LeaveCriticalSection(&g_lock);
    return buf;
}

const char *jobs_error(const Job *j) {
    static char buf[512];
    buf[0] = 0;
    if (!j) return buf;
    EnterCriticalSection(&g_lock);
    copy_into(buf, sizeof(buf), j->error);
    LeaveCriticalSection(&g_lock);
    return buf;
}

bool jobs_wait(const Job *j, int timeout_ms) {
    int64_t start = now_ms();
    while (true) {
        int s = 0;
        jobs_status(j, &s, NULL);
        if (s == 2 || s == 3) return true;
        if (now_ms() - start >= timeout_ms) return false;
        Sleep(10);
    }
}

void jobs_shutdown(void) {
    /* Per-job threads are self-terminating; nothing persistent to stop. */
}
