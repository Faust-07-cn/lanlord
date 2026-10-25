#ifndef LANMGR_NEIGHBOR_H
#define LANMGR_NEIGHBOR_H

#include <stdint.h>
#include <stdbool.h>

#define LANMGR_MAX_NEIGHBORS 1024

typedef struct {
    uint32_t ip;      /* network byte order */
    uint8_t  mac[6];
    uint32_t ifindex; /* interface index (scopes ARP rows to an interface) */
    int      type;    /* MIB_IPNET_TYPE_* (2 invalid, 3 dynamic, 4 static) */
} NeighborEntry;

typedef struct {
    int count;
    NeighborEntry entries[LANMGR_MAX_NEIGHBORS];
} NeighborTable;

/* Read the IPv4 ARP/neighbor cache (GetIpNetTable). Instant; tells "who is in use". */
int neighbor_discover(NeighborTable *nt);

/* Look up MAC by IP (any interface); returns true if found. */
bool neighbor_find(const NeighborTable *nt, uint32_t ip, uint8_t mac[6], int *type);

#endif
