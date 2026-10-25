#ifndef LANMGR_RISK_H
#define LANMGR_RISK_H

#include <stdint.h>
#include <stdbool.h>

typedef enum { RISK_READ = 0, RISK_WRITE = 1, RISK_DESTRUCTIVE = 2 } RiskLevel;

typedef struct {
    char     id[40];
    RiskLevel level;
    char     summary[512];
    char     detail[2048];   /* JSON params snapshot (already redacted) */
    int64_t  created_ms;
    int      timeout_s;
    int      decided;        /* 0 pending, 1 approved, 2 denied, 3 timeout */
    int64_t  decided_ms;
} Confirmation;

const char *risk_level_str(RiskLevel lvl);
bool risk_requires_confirm(RiskLevel lvl);

/* Create a pending confirmation; returns E_OK and fills out.id. */
int risk_request(RiskLevel lvl, const char *summary, const char *detail_json, int timeout_s, Confirmation *out);

/* Approve (true) or deny (false) a pending confirmation by id. */
int risk_decide(const char *id, bool approve);

/* Query a confirmation's decision: *decided is 0 pending,1 approved,2 denied,3 timeout. */
int risk_query(const char *id, int *decided);

/* Copy the full confirmation record (any state) by id. */
int risk_get(const char *id, Confirmation *out);

/* Fill up to max pending confirmations; auto-denies expired ones. Returns count. */
int risk_pending(Confirmation *out, int max);

int risk_init(void);
const char *risk_level_json_str(RiskLevel lvl); /* "read"/"write"/"destructive" */

#endif
