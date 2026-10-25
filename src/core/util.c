#include "wincompat.h"
#include "util.h"
#include "error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t ip_from_string(const char *s) {
    if (!s || !*s) return 0;
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) == 1) return a.s_addr; /* network byte order */
    return 0;
}

const char *ip_to_string(uint32_t ip, char *out, size_t len) {
    struct in_addr a;
    a.s_addr = ip;
    if (inet_ntop(AF_INET, &a, out, len) == NULL) return NULL;
    return out;
}

bool in_subnet(uint32_t ip, uint32_t addr, uint8_t prefix) {
    if (prefix > 32) return false;
    uint32_t mh = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
    uint32_t mask = htonl(mh);
    return (ip & mask) == (addr & mask);
}

uint32_t network_address(uint32_t addr, uint8_t prefix) {
    if (prefix > 32) prefix = 32;
    uint32_t mh = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
    return addr & htonl(mh);
}

bool is_private_ip(uint32_t ip) {
    return in_subnet(ip, ip_from_string("10.0.0.0"), 8)
        || in_subnet(ip, ip_from_string("172.16.0.0"), 12)
        || in_subnet(ip, ip_from_string("192.168.0.0"), 16);
}

bool is_loopback_ip(uint32_t ip) {
    /* 127.0.0.0/8: first octet == 127 */
    return (uint8_t)(ip & 0xFFu) == 127u;
}

bool is_multicast_ip(uint32_t ip) {
    /* 224.0.0.0/4: first octet 224..239 */
    return ((uint8_t)(ip & 0xFFu) & 0xF0u) == 0xE0u;
}

bool is_broadcast_ip(uint32_t ip) {
    return ip == 0xFFFFFFFFu;
}

void zeroize(void *p, size_t n) {
    if (p && n) SecureZeroMemory(p, n);
}

char *lstrdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

void *lxcalloc(size_t n, size_t sz) { return calloc(n, sz); }
void *lxmalloc(size_t n) { return malloc(n); }

int64_t now_ms(void) { return (int64_t)GetTickCount64(); }

void mac_format(const unsigned char mac[6], char *out, size_t len) {
    snprintf(out, len, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void gen_id(char *out, size_t len) {
    static volatile LONG counter = 0;
    LONG c = InterlockedIncrement(&counter);
    snprintf(out, len, "%lld-%ld", (long long)GetTickCount64(), c);
}

char *wcs_to_utf8(const wchar_t *w, char *out, size_t len) {
    if (!out || len == 0) return out;
    if (!w) { out[0] = 0; return out; }
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (n <= 0) { out[0] = 0; return out; }
    if ((size_t)n > len) n = (int)len;
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, n, NULL, NULL);
    out[len - 1] = 0;
    return out;
}

const char *err_str(int code) {
    switch (code) {
        case E_OK:          return "ok";
        case E_ARG:         return "invalid argument";
        case E_NOMEM:       return "out of memory";
        case E_IO:          return "i/o error";
        case E_NOTFOUND:    return "not found";
        case E_AUTH:        return "authentication failed";
        case E_DENIED:      return "denied by user";
        case E_TIMEOUT:     return "timed out";
        case E_NET:         return "network error";
        case E_UNSUPPORTED: return "unsupported";
        case E_INTERNAL:    return "internal error";
        default:            return "unknown error";
    }
}
