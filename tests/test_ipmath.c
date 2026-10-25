#include "core/util.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, name) do { if (cond) { printf("PASS %s\n", name); } \
    else { printf("FAIL %s\n", name); fails++; } } while (0)

int main(void) {
    char b[16];

    uint32_t ip = ip_from_string("192.168.31.59");
    CHECK(ip != 0, "ip_from_string non-zero");
    CHECK(strcmp(ip_to_string(ip, b, sizeof(b)), "192.168.31.59") == 0, "ip round-trip");

    CHECK(in_subnet(ip_from_string("192.168.31.59"), ip_from_string("192.168.31.0"), 24), "in /24 true");
    CHECK(!in_subnet(ip_from_string("192.168.32.1"), ip_from_string("192.168.31.0"), 24), "outside /24 false");
    CHECK(in_subnet(ip_from_string("10.1.2.3"), ip_from_string("10.0.0.0"), 8), "10/8 true");
    CHECK(in_subnet(ip_from_string("172.20.1.1"), ip_from_string("172.16.0.0"), 12), "172.16/12 true");

    CHECK(is_private_ip(ip_from_string("10.0.0.1")), "10.x private");
    CHECK(is_private_ip(ip_from_string("172.16.0.1")), "172.16 private");
    CHECK(is_private_ip(ip_from_string("192.168.1.1")), "192.168 private");
    CHECK(!is_private_ip(ip_from_string("198.18.0.1")), "198.18 not private (fake-ip)");
    CHECK(!is_private_ip(ip_from_string("8.8.8.8")), "8.8.8.8 not private");

    CHECK(is_multicast_ip(ip_from_string("224.0.0.2")), "224/4 multicast");
    CHECK(is_multicast_ip(ip_from_string("239.255.255.250")), "239 multicast");
    CHECK(!is_multicast_ip(ip_from_string("192.168.31.1")), "192.168 unicast");
    CHECK(is_broadcast_ip(ip_from_string("255.255.255.255")), "255 broadcast");
    CHECK(is_loopback_ip(ip_from_string("127.0.0.1")), "loopback");

    uint32_t net = network_address(ip_from_string("192.168.31.99"), 24);
    CHECK(strcmp(ip_to_string(net, b, sizeof(b)), "192.168.31.0") == 0, "network_address /24");

    printf("\n%s (%d failure(s))\n", fails == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED", fails);
    return fails == 0 ? 0 : 1;
}
