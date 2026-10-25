#ifndef LANMGR_UTIL_H
#define LANMGR_UTIL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ---------- IPv4 math (values stored in NETWORK byte order, as in_addr.s_addr) ---------- */

/* Parse dotted-quad into network-byte-order uint32. Returns 0 on failure
 * (0.0.0.0 is a valid address but treated as "invalid" here; acceptable for LAN use). */
uint32_t ip_from_string(const char *s);

/* Format network-byte-order uint32 into dotted-quad. Returns out on success, NULL otherwise. */
const char *ip_to_string(uint32_t ip, char *out, size_t len);

/* True if ip belongs to the subnet described by addr/prefix (both network byte order). */
bool in_subnet(uint32_t ip, uint32_t addr, uint8_t prefix);

/* Compute the network base address of addr/prefix. */
uint32_t network_address(uint32_t addr, uint8_t prefix);

/* RFC1918 private space (10/8, 172.16/12, 192.168/16). */
bool is_private_ip(uint32_t ip);

/* 127.0.0.0/8 loopback. */
bool is_loopback_ip(uint32_t ip);

/* 224.0.0.0/4 multicast, and 255.255.255.255 broadcast helper. */
bool is_multicast_ip(uint32_t ip);
bool is_broadcast_ip(uint32_t ip);

/* ---------- memory / string helpers ---------- */

/* Overwrite memory so optimizers cannot elide it (wraps SecureZeroMemory). */
void zeroize(void *p, size_t n);

char *lstrdup(const char *s);
void *lxcalloc(size_t n, size_t sz);
void *lxmalloc(size_t n);

/* Monotonic milliseconds since boot. */
int64_t now_ms(void);

/* Upper-case hex MAC, e.g. "A0:1B:2C:3D:4E:5F". */
void mac_format(const unsigned char mac[6], char *out, size_t len);

/* Short unique id, e.g. "1234567890-7". */
void gen_id(char *out, size_t len);

/* Convert a wide (UTF-16) Windows string to UTF-8. Returns out. */
char *wcs_to_utf8(const wchar_t *w, char *out, size_t len);

#endif
