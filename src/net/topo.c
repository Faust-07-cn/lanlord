#include "wincompat.h"
#include "topo.h"
#include "iface.h"
#include "neighbor.h"
#include "probe.h"
#include "name.h"
#include "util.h"
#include "error.h"
#include "log.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef enum { NODE_ROOT = 0, NODE_SUBNET = 1, NODE_GATEWAY = 2, NODE_SWITCH = 3, NODE_AP = 4, NODE_HOST = 5, NODE_UNKNOWN = 6 } NodeType;

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

static DeviceNode *build_tree(const NetInfo *ni, const NeighborTable *nt, const AliveList *al) {
    DeviceNode *root = node_new(NODE_ROOT);
    snprintf(root->id, sizeof(root->id), "root");
    snprintf(root->label, sizeof(root->label), "局域网");
    root->active = true;

    char ipbuf[16];

    for (int si = 0; si < ni->subnet_count; si++) {
        const Subnet *s = &ni->subnets[si];

        /* Ignore segments outside the LAN (proxy/fake-IP, public direct, APIPA...). */
        if (!is_private_ip(s->ip)) {
            LOGI("忽略非局域网网段 %s (ifname=%s)",
                 ip_to_string(s->ip, (char[16]){0}, 16), s->ifname);
            continue;
        }

        DeviceNode *sub = node_new(NODE_SUBNET);
        snprintf(sub->id, sizeof(sub->id), "subnet-%d", si);
        snprintf(ipbuf, sizeof(ipbuf), "%s", ip_to_string(network_address(s->ip, s->prefix), (char[16]){0}, 16));
        snprintf(sub->label, sizeof(sub->label), "%s/%d · %s", ipbuf, s->prefix,
                 s->ifname[0] ? s->ifname : "接口");
        sub->ip = network_address(s->ip, s->prefix);
        sub->prefix = s->prefix;
        sub->active = true;
        snprintf(sub->ifname, sizeof(sub->ifname), "%s", s->ifname);

        /* Gateway / upstream router node. */
        if (s->has_gateway && !bad_ip(s->gateway)) {
            DeviceNode *gw = node_new(NODE_GATEWAY);
            snprintf(gw->id, sizeof(gw->id), "gw-%d", si);
            snprintf(ipbuf, sizeof(ipbuf), "%s", ip_to_string(s->gateway, (char[16]){0}, 16));
            uint8_t m[6] = {0}; int t = 0;
            if (neighbor_find(nt, s->gateway, m, &t) && !bad_mac(m)) {
                set_oui(gw, m);
            }
            gw->type = NODE_GATEWAY;
            snprintf(gw->label, sizeof(gw->label), "%s（上级路由）", ipbuf);
            if (gw->vendor[0] && strcmp(gw->vendor, "unknown") != 0)
                snprintf(gw->label, sizeof(gw->label), "%s（上级路由 · %s）", ipbuf, gw->vendor);
            gw->ip = s->gateway;
            gw->active = true;
            add_child(sub, gw);
        }

        /* Hosts: ARP rows scoped to this interface (already "in use") + live ping results. */
        uint32_t seen[LANMGR_MAX_ALIVE];
        int nseen = 0;

        uint32_t base = network_address(s->ip, s->prefix);
        uint32_t hostmask = (s->prefix == 0) ? 0xFFFFFFFFu : (0xFFFFFFFFu >> s->prefix);
        uint32_t bcast = base | htonl(hostmask);

        for (int k = 0; k < nt->count; k++) {
            const NeighborEntry *e = &nt->entries[k];
            if (e->ifindex != s->ifindex) continue;               /* scope to this interface */
            uint32_t ip = e->ip;
            if (bad_ip(ip) || bad_mac(e->mac)) continue;
            if (ip == base || ip == bcast) continue;
            if (is_self(ni, ip)) continue;
            if (ip == s->gateway) continue;                        /* already a gateway node */
            if (e->type == 2) continue;                            /* invalid ARP row */
            push_seen(seen, &nseen, LANMGR_MAX_ALIVE, ip);
        }
        for (int k = 0; k < al->count; k++) {
            uint32_t ip = al->ips[k];
            if (!in_subnet(ip, s->ip, s->prefix)) continue;
            if (bad_ip(ip)) continue;
            if (ip == base || ip == bcast) continue;
            if (is_self(ni, ip)) continue;
            if (ip == s->gateway) continue;
            push_seen(seen, &nseen, LANMGR_MAX_ALIVE, ip);
        }

        for (int k = 0; k < nseen; k++) {
            uint32_t ip = seen[k];
            DeviceNode *h = node_new(NODE_HOST);
            snprintf(ipbuf, sizeof(ipbuf), "%s", ip_to_string(ip, (char[16]){0}, 16));
            snprintf(h->id, sizeof(h->id), "host-%s", ipbuf);
            uint8_t mac[6]; int t = 0;
            bool have = neighbor_find(nt, ip, mac, &t);
            if (have && !bad_mac(mac)) set_oui(h, mac);
            else { snprintf(h->vendor, sizeof(h->vendor), "unknown"); h->type = NODE_HOST; }
            snprintf(h->label, sizeof(h->label), "%s", ipbuf);
            if (h->vendor[0] && strcmp(h->vendor, "unknown") != 0)
                snprintf(h->label, sizeof(h->label), "%s · %s", ipbuf, h->vendor);
            h->ip = ip;
            h->active = true;
            add_child(sub, h);
        }

        if (sub->children) add_child(root, sub);
        else free(sub);
    }

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

char *net_discover(int sweep_timeout_ms, int max_hosts) {
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

    DeviceNode *root = build_tree(&ni, &nt, &al);
    cJSON *j = serialize_node(root);
    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    node_free(root);
    return s;
}
