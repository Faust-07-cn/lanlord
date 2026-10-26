#include "wincompat.h"
#include "topo.h"
#include "iface.h"
#include "neighbor.h"
#include "probe.h"
#include "name.h"
#include "traceroute.h"
#include "gateway.h"
#include "util.h"
#include "error.h"
#include "log.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef enum { NODE_ROOT = 0, NODE_SUBNET = 1, NODE_GATEWAY = 2, NODE_SWITCH = 3, NODE_AP = 4, NODE_HOST = 5, NODE_UNKNOWN = 6, NODE_UPSTREAM = 7 } NodeType;

typedef struct DeviceNode {
    char     id[40];
    NodeType type;
    uint32_t ip;          /* network byte order; 0 for root */
    uint8_t  prefix;
    uint8_t  mac[6];
    bool     has_mac;
    char     label[256];
    char     vendor[64];
    char     ifname[128];
    bool     active;
    struct DeviceNode *next;
    struct DeviceNode *children;
} DeviceNode;

static const char *type_str(NodeType t) {
    switch (t) {
        case NODE_ROOT: return "root";
        case NODE_SUBNET: return "subnet";
        case NODE_GATEWAY: return "gateway";
        case NODE_SWITCH: return "switch";
        case NODE_AP: return "ap";
        case NODE_HOST: return "host";
        case NODE_UPSTREAM: return "upstream";
        default: return "unknown";
    }
}

static bool vendor_is_networking(const char *v) {
    static const char *NET[] = {"TP-Link","Cisco","Ubiquiti","MikroTik","D-Link","NETGEAR",
        "ASUS","Tenda","Huawei","H3C","Xiaomi","Linksys","Aruba","Ruckus","ZTE","Hikvision"};
    for (size_t i = 0; i < sizeof(NET)/sizeof(NET[0]); i++) if (strcmp(v, NET[i]) == 0) return true;
    return false;
}

/* IPs that are never "user devices". */
static bool bad_ip(uint32_t ip) {
    return is_multicast_ip(ip) || is_broadcast_ip(ip) || is_loopback_ip(ip);
}
/* Multicast/broadcast MACs (bit0 of first octet set), plus all-zero. */
static bool bad_mac(const uint8_t mac[6]) {
    int sum = 0;
    for (int i = 0; i < 6; i++) sum += mac[i];
    if (sum == 0) return true;
    return (mac[0] & 0x01u) != 0;
}

static DeviceNode *node_new(NodeType t) {
    DeviceNode *n = (DeviceNode *)calloc(1, sizeof(DeviceNode));
    if (n) n->type = t;
    return n;
}

static void add_child(DeviceNode *parent, DeviceNode *child) {
    if (!parent->children) parent->children = child;
    else { DeviceNode *c = parent->children; while (c->next) c = c->next; c->next = child; }
}

static void set_oui(DeviceNode *n, const uint8_t mac[6]) {
    n->has_mac = true;
    memcpy(n->mac, mac, 6);
    const char *v = oui_vendor(mac);
    snprintf(n->vendor, sizeof(n->vendor), "%s", v);
    if (vendor_is_networking(v)) {
        if (strcmp(v,"Huawei")==0 || strcmp(v,"H3C")==0 || strcmp(v,"Cisco")==0 ||
            strcmp(v,"MikroTik")==0 || strcmp(v,"Ubiquiti")==0) n->type = NODE_SWITCH;
        else n->type = NODE_AP;
    } else {
        n->type = NODE_HOST;
    }
}

static bool is_self(const NetInfo *ni, uint32_t ip) {
    if (ip == ni->self_ip) return true;
    for (int i = 0; i < ni->subnet_count; i++) if (ni->subnets[i].ip == ip) return true;
    return false;
}

/* Append ip to a deduped list. */
static void push_seen(uint32_t *seen, int *n, int cap, uint32_t ip) {
    if (*n >= cap) return;
    for (int m = 0; m < *n; m++) if (seen[m] == ip) return;
    seen[(*n)++] = ip;
}

static const char *router_friendly(const char *vendor) {
    if (!strcmp(vendor, "Xiaomi")) return "小米";
    if (!strcmp(vendor, "Huawei")) return "华为";
    if (!strcmp(vendor, "H3C")) return "H3C";
    if (!strcmp(vendor, "TP-Link")) return "TP-Link";
    if (!strcmp(vendor, "Tenda")) return "腾达";
    if (!strcmp(vendor, "NETGEAR")) return "NETGEAR";
    if (!strcmp(vendor, "Cisco")) return "Cisco";
    if (!strcmp(vendor, "Ubiquiti")) return "Ubiquiti";
    if (!strcmp(vendor, "MikroTik")) return "MikroTik";
    if (!strcmp(vendor, "D-Link")) return "D-Link";
    if (!strcmp(vendor, "ASUS")) return "ASUS";
    return vendor;
}

/* Build the local LAN subtree: returns the GATEWAY node (top of the LAN), with the active
 * hosts attached directly beneath it. Uses the primary subnet (default-gateway one first). */
static DeviceNode *build_lan_subtree(const NetInfo *ni, const NeighborTable *nt, const AliveList *al) {
    char ipbuf[16];
    int pi = -1;

    if (ni->has_default) {
        for (int i = 0; i < ni->subnet_count; i++)
            if (ni->subnets[i].has_gateway && ni->subnets[i].gateway == ni->default_gateway) { pi = i; break; }
    }
    if (pi < 0)
        for (int i = 0; i < ni->subnet_count; i++)
            if (is_private_ip(ni->subnets[i].ip) && ni->subnets[i].has_gateway) { pi = i; break; }
    if (pi < 0)
        for (int i = 0; i < ni->subnet_count; i++)
            if (is_private_ip(ni->subnets[i].ip)) { pi = i; break; }
    if (pi < 0) return NULL;

    const Subnet *s = &ni->subnets[pi];
    uint32_t gw_ip = s->has_gateway ? s->gateway : s->ip;

    DeviceNode *gw = node_new(NODE_GATEWAY);
    snprintf(gw->id, sizeof(gw->id), "gw");
    ip_to_string(gw_ip, ipbuf, sizeof(ipbuf));
    uint8_t m[6] = {0}; int t = 0;
    if (s->has_gateway && neighbor_find(nt, gw_ip, m, &t) && !bad_mac(m)) set_oui(gw, m);
    gw->type = NODE_GATEWAY;
    if (gw->vendor[0] && strcmp(gw->vendor, "unknown") != 0)
        snprintf(gw->label, sizeof(gw->label), "网关 %s · %s（%s）", ipbuf,
                 s->ifname[0] ? s->ifname : "接口", router_friendly(gw->vendor));
    else
        snprintf(gw->label, sizeof(gw->label), "网关 %s · %s", ipbuf, s->ifname[0] ? s->ifname : "接口");
    gw->ip = gw_ip;
    gw->prefix = s->prefix;
    gw->active = true;

    uint32_t seen[LANMGR_MAX_ALIVE];
    int nseen = 0;
    uint32_t base = network_address(s->ip, s->prefix);
    uint32_t hostmask = (s->prefix == 0) ? 0xFFFFFFFFu : (0xFFFFFFFFu >> s->prefix);
    uint32_t bcast = base | htonl(hostmask);

    for (int k = 0; k < nt->count; k++) {
        const NeighborEntry *e = &nt->entries[k];
        if (e->ifindex != s->ifindex) continue;
        uint32_t ip = e->ip;
        if (bad_ip(ip) || bad_mac(e->mac)) continue;
        if (ip == base || ip == bcast) continue;
        if (is_self(ni, ip)) continue;
        if (ip == gw_ip) continue;
        if (e->type == 2) continue;
        push_seen(seen, &nseen, LANMGR_MAX_ALIVE, ip);
    }
    for (int k = 0; k < al->count; k++) {
        uint32_t ip = al->ips[k];
        if (!in_subnet(ip, s->ip, s->prefix)) continue;
        if (bad_ip(ip)) continue;
        if (ip == base || ip == bcast) continue;
        if (is_self(ni, ip)) continue;
        if (ip == gw_ip) continue;
        push_seen(seen, &nseen, LANMGR_MAX_ALIVE, ip);
    }
    for (int k = 0; k < nseen; k++) {
        uint32_t ip = seen[k];
        DeviceNode *h = node_new(NODE_HOST);
        ip_to_string(ip, ipbuf, sizeof(ipbuf));
        snprintf(h->id, sizeof(h->id), "host-%s", ipbuf);
        uint8_t mac[6]; int tt = 0;
        bool have = neighbor_find(nt, ip, mac, &tt);
        if (have && !bad_mac(mac)) set_oui(h, mac);
        else { snprintf(h->vendor, sizeof(h->vendor), "unknown"); h->type = NODE_HOST; }
        snprintf(h->label, sizeof(h->label), "%s", ipbuf);
        if (h->vendor[0] && strcmp(h->vendor, "unknown") != 0)
            snprintf(h->label, sizeof(h->label), "%s · %s", ipbuf, h->vendor);
        h->ip = ip;
        h->active = true;
        add_child(gw, h);
    }
    return gw;
}

/* Trace upward from the local host to discover the wired router cascade (multi-level NAT).
 * Traceroute to several targets and keep the deepest path so a single short/obscured path
 * cannot hide routers; each level is tagged 内网/公网 + level number. */
static int cmp_hop_dist(const void *a, const void *b) {
    const GwHop *x = (const GwHop *)a, *y = (const GwHop *)b;
    return x->distance - y->distance;
}

/* Assemble the full topology with the 光猫 (ONT) as the ROOT, organized top-down:
 *   光猫 -> 华为/上游路由 -> 本地网关 -> 活动主机 */
static DeviceNode *assemble_tree(const NetInfo *ni, const NeighborTable *nt, const AliveList *al, int trace_upstream) {
    DeviceNode *lan = build_lan_subtree(ni, nt, al);

    if (trace_upstream) {
        GwHop up[32];
        int n = gateway_scan(ni->self_ip, ni->default_gateway, 400, up, 32);
        int m = 0;
        for (int i = 0; i < n; i++) if (up[i].distance <= 3) up[m++] = up[i];
        n = m;
        if (n > 0) {
            qsort(up, (size_t)n, sizeof(up[0]), cmp_hop_dist);
            DeviceNode *nodes[32];
            char ipbuf[16];
            for (int i = 0; i < n; i++) {
                ip_to_string(up[i].ip, ipbuf, sizeof(ipbuf));
                char brand[64] = "";
                gateway_brand(up[i].ip, brand, sizeof(brand));

                DeviceNode *nd = node_new(NODE_UPSTREAM);
                snprintf(nd->id, sizeof(nd->id), "upstream-%d", i);
                bool is_ont = strstr(brand, "光猫") != NULL;
                bool farthest = (i == n - 1);
                if (is_ont || farthest) {
                    if (is_ont) snprintf(nd->label, sizeof(nd->label), "光猫 %s（%s）", ipbuf, brand);
                    else snprintf(nd->label, sizeof(nd->label), "光猫 %s（上级边界）", ipbuf);
                } else {
                    if (brand[0]) snprintf(nd->label, sizeof(nd->label), "上游路由 %s（%s）", ipbuf, brand);
                    else snprintf(nd->label, sizeof(nd->label), "上游路由 %s", ipbuf);
                }
                nd->ip = up[i].ip;
                nd->active = true;
                nodes[i] = nd;
            }
            /* farthest = 光猫 = root; chain downward to the nearest router, then LAN subtree */
            DeviceNode *root = nodes[n - 1];
            for (int i = n - 1; i > 0; i--) add_child(nodes[i], nodes[i - 1]);
            if (lan) add_child(nodes[0], lan);
            return root;
        }
    }

    DeviceNode *root = node_new(NODE_ROOT);
    snprintf(root->id, sizeof(root->id), "root");
    snprintf(root->label, sizeof(root->label), "局域网");
    root->active = true;
    if (lan) add_child(root, lan);
    return root;
}

static cJSON *serialize_node(const DeviceNode *n) {
    cJSON *o = cJSON_CreateObject();
    char ipbuf[16];
    cJSON_AddStringToObject(o, "id", n->id);
    cJSON_AddStringToObject(o, "type", type_str(n->type));
    if (n->ip) { ip_to_string(n->ip, ipbuf, sizeof(ipbuf)); cJSON_AddStringToObject(o, "ip", ipbuf); }
    if (n->prefix) cJSON_AddNumberToObject(o, "prefix", n->prefix);
    if (n->has_mac) { char m[20]; mac_format(n->mac, m, sizeof(m)); cJSON_AddStringToObject(o, "mac", m); }
    if (n->vendor[0]) cJSON_AddStringToObject(o, "vendor", n->vendor);
    if (n->label[0]) cJSON_AddStringToObject(o, "label", n->label);
    if (n->ifname[0]) cJSON_AddStringToObject(o, "ifname", n->ifname);
    cJSON_AddBoolToObject(o, "active", n->active ? 1 : 0);

    if (n->children) {
        cJSON *kids = cJSON_CreateArray();
        for (DeviceNode *c = n->children; c; c = c->next) cJSON_AddItemToArray(kids, serialize_node(c));
        cJSON_AddItemToObject(o, "children", kids);
    }
    return o;
}

static void node_free(DeviceNode *n) {
    DeviceNode *c = n->children;
    while (c) { DeviceNode *nx = c->next; node_free(c); c = nx; }
    free(n);
}

char *net_discover(int sweep_timeout_ms, int max_hosts, int trace_upstream) {
    if (sweep_timeout_ms <= 0) sweep_timeout_ms = 400;
    if (max_hosts <= 0) max_hosts = 256;

    NetInfo ni;
    if (iface_discover(&ni) != E_OK) { LOGE("interface discovery failed"); return NULL; }
    char gwb[16];
    LOGI("local subnets=%d default_gw=%s", ni.subnet_count,
         ni.has_default ? ip_to_string(ni.default_gateway, gwb, sizeof(gwb)) : "(none)");

    NeighborTable nt;
    neighbor_discover(&nt);

    AliveList al;
    memset(&al, 0, sizeof(al));
    for (int i = 0; i < ni.subnet_count; i++) {
        AliveList tmp;
        probe_sweep(&ni.subnets[i], sweep_timeout_ms, max_hosts, &tmp);
        for (int k = 0; k < tmp.count && al.count < LANMGR_MAX_ALIVE; k++)
            push_seen(al.ips, &al.count, LANMGR_MAX_ALIVE, tmp.ips[k]);
    }

    DeviceNode *root = assemble_tree(&ni, &nt, &al, trace_upstream);
    cJSON *j = serialize_node(root);
    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    node_free(root);
    return s;
}
