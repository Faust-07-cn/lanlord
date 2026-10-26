#ifndef LANMGR_GATEWAY_H
#define LANMGR_GATEWAY_H

#include <stdint.h>
#include <stddef.h>

typedef struct { uint32_t ip; int distance; } GwHop;

/* Ping a curated list of common private router/光猫 gateway addresses; for each responder
 * record its hop distance (derived from the reply TTL). Works even when a TUN proxy masks
 * traceroute (private traffic is usually routed directly). */
int gateway_scan(uint32_t self_ip, uint32_t local_gw, int timeout_ms, GwHop *out, int max);

/* Identify a gateway by its HTTP login-page title (best effort, 2s timeout). Writes a short
 * brand label like "光猫·中国移动" / "华为路由" / "小米路由", or "" when unknown. */
int gateway_brand(uint32_t ip, char *out, size_t outlen);

#endif
