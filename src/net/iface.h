#ifndef LANMGR_IFACE_H
#define LANMGR_IFACE_H

#include <stdint.h>
#include <stdbool.h>

#define LANMGR_MAX_SUBNETS 32

typedef struct {
    char     ifname[128];   /* adapter friendly name (UTF-8) */
    uint32_t ifindex;       /* interface index (for scoping ARP rows) */
    uint32_t ip;            /* network byte order */
    uint8_t  prefix;        /* 0..32 */
    uint32_t gateway;       /* network byte order; 0 if none */
    bool     has_gateway;
} Subnet;

typedef struct {
    int       subnet_count;
    Subnet    subnets[LANMGR_MAX_SUBNETS];
    uint32_t  default_gateway; /* upstream router (next hop of 0.0.0.0/0) */
    bool      has_default;
    uint32_t  self_ip;         /* our own IPv4 on the uplink */
} NetInfo;

/* Enumerate active IPv4 interfaces + subnets + default gateway (upstream router). */
int  iface_discover(NetInfo *ni);

/* True if ip belongs to any enumerated subnet (i.e. inside our LAN). */
bool iface_in_lan(const NetInfo *ni, uint32_t ip);

#endif
