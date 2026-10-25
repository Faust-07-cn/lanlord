#include "wincompat.h"
#include "iface.h"
#include "util.h"
#include "error.h"
#include "log.h"
#include <iphlpapi.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef GAA_FLAG_INCLUDE_GATEWAYS
#define GAA_FLAG_INCLUDE_GATEWAYS 0x0080
#endif

int iface_discover(NetInfo *ni) {
    memset(ni, 0, sizeof(*ni));

    /* 1) default gateway (上级路由器) from the IPv4 routing table. */
    ULONG sz = 0;
    if (GetIpForwardTable(NULL, &sz, FALSE) == ERROR_INSUFFICIENT_BUFFER && sz > 0) {
        PMIB_IPFORWARDTABLE ft = (PMIB_IPFORWARDTABLE)malloc(sz);
        if (ft) {
            if (GetIpForwardTable(ft, &sz, FALSE) == NO_ERROR) {
                for (DWORD i = 0; i < ft->dwNumEntries; i++) {
                    MIB_IPFORWARDROW *r = &ft->table[i];
                    if (r->dwForwardDest == 0 && r->dwForwardMask == 0 && r->dwForwardNextHop != 0) {
                        ni->default_gateway = r->dwForwardNextHop;
                        ni->has_default = true;
                        break;
                    }
                }
            }
            free(ft);
        }
    }

    /* 2) adapters and per-adapter subnets/gateways. */
    ULONG buflen = 0;
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS;
    if (GetAdaptersAddresses(AF_INET, flags, NULL, NULL, &buflen) != ERROR_BUFFER_OVERFLOW) {
        LOGW("GetAdaptersAddresses probe failed");
        return E_IO;
    }
    PIP_ADAPTER_ADDRESSES aa = (PIP_ADAPTER_ADDRESSES)malloc(buflen);
    if (!aa) return E_NOMEM;
    if (GetAdaptersAddresses(AF_INET, flags, NULL, aa, &buflen) != NO_ERROR) { free(aa); return E_IO; }

    for (PIP_ADAPTER_ADDRESSES a = aa; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK || a->IfType == IF_TYPE_TUNNEL) continue;

        for (PIP_ADAPTER_UNICAST_ADDRESS u = a->FirstUnicastAddress; u; u = u->Next) {
            if (u->Address.lpSockaddr->sa_family != AF_INET) continue;
            uint32_t ip = ((const struct sockaddr_in *)u->Address.lpSockaddr)->sin_addr.s_addr;
            if (ip == 0 || is_loopback_ip(ip)) continue;

            uint32_t gw = 0; bool has_gw = false;
            for (PIP_ADAPTER_GATEWAY_ADDRESS g = a->FirstGatewayAddress; g; g = g->Next) {
                if (g->Address.lpSockaddr->sa_family == AF_INET) {
                    gw = ((const struct sockaddr_in *)g->Address.lpSockaddr)->sin_addr.s_addr;
                    if (gw != 0) has_gw = true;
                    break;
                }
            }

            if (ni->subnet_count < LANMGR_MAX_SUBNETS) {
                Subnet *s = &ni->subnets[ni->subnet_count++];
                memset(s, 0, sizeof(*s));
                wcs_to_utf8(a->FriendlyName, s->ifname, sizeof(s->ifname));
                s->ifindex = (uint32_t)a->IfIndex;
                s->ip = ip;
                s->prefix = (uint8_t)u->OnLinkPrefixLength;
                s->gateway = gw;
                s->has_gateway = has_gw;
            }
        }
    }

    /* Our own IP = interface whose gateway matches the default gateway, else first. */
    if (ni->has_default) {
        for (int i = 0; i < ni->subnet_count; i++) {
            if (ni->subnets[i].has_gateway && ni->subnets[i].gateway == ni->default_gateway) {
                ni->self_ip = ni->subnets[i].ip; break;
            }
        }
    }
    if (ni->self_ip == 0 && ni->subnet_count > 0) ni->self_ip = ni->subnets[0].ip;

    free(aa);
    return E_OK;
}

bool iface_in_lan(const NetInfo *ni, uint32_t ip) {
    for (int i = 0; i < ni->subnet_count; i++) {
        if (in_subnet(ip, ni->subnets[i].ip, ni->subnets[i].prefix)) return true;
    }
    return false;
}
