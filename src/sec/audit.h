#ifndef LANMGR_AUDIT_H
#define LANMGR_AUDIT_H

int audit_init(const char *path);

/* Append an audit record (JSON line). decision e.g. "approved"/"denied"/"timeout"/"executed". */
void audit_log(const char *actor, const char *action, const char *target,
               const char *decision, const char *detail);

#endif
