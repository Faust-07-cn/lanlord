#ifndef LANMGR_TRACEROUTE_H
#define LANMGR_TRACEROUTE_H

#include <stdint.h>

#define TR_MAX_HOPS 16

typedef struct { uint32_t ip; int hop; } TraceHop;
typedef struct { int count; TraceHop hops[TR_MAX_HOPS]; } TraceResult;

/* Trace the route to "target" using the system tracert.exe (-d, no name resolution).
 * Parses hop IPs (in order) into out. Returns E_OK (0) on success. */
int traceroute_run(const char *target, int max_hops, int timeout_ms, TraceResult *out);

#endif
