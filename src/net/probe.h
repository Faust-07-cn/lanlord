#ifndef LANMGR_PROBE_H
#define LANMGR_PROBE_H

#include <stdint.h>
#include "iface.h"

#define LANMGR_MAX_ALIVE 2048

typedef struct {
    uint32_t ips[LANMGR_MAX_ALIVE]; /* network byte order */
    int count;
} AliveList;

/* Ping-sweep a subnet (only /24 and smaller are swept in full; larger are skipped).
 * Returns E_OK on success (0 alive if skipped), stores responding host IPs (excluding
 * network/broadcast) into *out. */
int probe_sweep(const Subnet *sub, int timeout_ms, int max_hosts, AliveList *out);

#endif
