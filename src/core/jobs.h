#ifndef LANMGR_JOBS_H
#define LANMGR_JOBS_H

#include <stddef.h>
#include <stdbool.h>

typedef struct Job Job;

/* Run function: produce output into outbuf (NUL-terminated), return 0 on success. */
typedef int (*JobRunFn)(Job *job, char *outbuf, size_t outlen);
typedef void (*JobCleanupFn)(void *ctx);

struct Job {
    int  id;
    char kind[40];
    void *ctx;
    JobRunFn run;
    JobCleanupFn cleanup;
    int  status;    /* 0 queued, 1 running, 2 done, 3 failed */
    int  progress;  /* 0..100 */
    char result[8192];
    char error[512];
    struct Job *next;
};

int  jobs_init(void);
Job *jobs_submit(const char *kind, void *ctx, JobRunFn run, JobCleanupFn cleanup);
Job *jobs_find(int id);
void jobs_progress_set(Job *j, int progress);
void jobs_status(const Job *j, int *status, int *progress);
const char *jobs_result(const Job *j);
const char *jobs_error(const Job *j);
bool jobs_wait(const Job *j, int timeout_ms);
void jobs_shutdown(void);

#endif
