#ifndef LANMGR_TOPO_H
#define LANMGR_TOPO_H

#include <stdint.h>

/* Run the full discovery pipeline (interfaces->gateway, ARP, ping sweep) and return a
 * malloc'd JSON string describing the LAN as a tree. Caller must free(). */
char *net_discover(int sweep_timeout_ms, int max_hosts);

#endif
