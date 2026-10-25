#include "wincompat.h"
#include "neighbor.h"
#include "util.h"
#include "error.h"
#include "log.h"
#include <iphlpapi.h>
#include <stdlib.h>
#include <string.h>

int neighbor_discover(NeighborTable *nt) {
    memset(nt, 0, sizeof(*nt));

    ULONG sz = 0;
    if (GetIpNetTable(NULL, &sz, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
        LOGW("GetIpNetTable probe failed");
        return E_IO;
    }
    PMIB_IPNETTABLE t = (PMIB_IPNETTABLE)malloc(sz);
    if (!t) return E_NOMEM;
    if (GetIpNetTable(t, &sz, FALSE) != NO_ERROR) { free(t); return E_IO; }

    for (DWORD i = 0; i < t->dwNumEntries && nt->count < LANMGR_MAX_NEIGHBORS; i++) {
        MIB_IPNETROW *r = &t->table[i];
        if (r->dwPhysAddrLen != 6) continue;
        if (r->dwAddr == 0) continue;
        NeighborEntry *e = &nt->entries[nt->count++];
        e->ip = r->dwAddr;
        memcpy(e->mac, r->bPhysAddr, 6);
        e->ifindex = (uint32_t)r->dwIndex;
        e->type = (int)r->dwType;
    }
    free(t);
    LOGI("neighbor cache: %d IPv4 entries", nt->count);
    return E_OK;
}

bool neighbor_find(const NeighborTable *nt, uint32_t ip, uint8_t mac[6], int *type) {
    for (int i = 0; i < nt->count; i++) {
        if (nt->entries[i].ip == ip) {
            if (mac) memcpy(mac, nt->entries[i].mac, 6);
            if (type) *type = nt->entries[i].type;
            return true;
        }
    }
    return false;
}
