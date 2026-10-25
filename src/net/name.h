#ifndef LANMGR_NAME_H
#define LANMGR_NAME_H

#include <stdint.h>
#include <stddef.h>

/* Vendor/family hint from MAC OUI (uppercase, e.g. "TP-Link"). Returns "unknown" if unmatched. */
const char *oui_vendor(const uint8_t mac[6]);

/* Best-effort reverse-DNS hostname. Returns 0 on success. (bounded; may be empty) */
int resolve_name(uint32_t ip, char *out, size_t len);

#endif
