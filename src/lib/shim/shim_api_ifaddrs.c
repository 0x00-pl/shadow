/*
 * The Shadow Simulator
 * See LICENSE for licensing information
 */
#include "lib/shim/shim_api_c.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <netdb.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

void shimc_api_freeifaddrs(struct ifaddrs* ifa);

int shimc_api_getifaddrs(struct ifaddrs** ifap) {
    if (!ifap) {
        errno = EFAULT;
        return -1;
    }

    /* we always have loopback */
    struct ifaddrs* head = calloc(1, sizeof(struct ifaddrs));
    struct ifaddrs* i = head;
    i->ifa_flags = (IFF_UP | IFF_RUNNING | IFF_LOOPBACK);
    i->ifa_name = strdup("lo");

    i->ifa_addr = calloc(1, sizeof(struct sockaddr));
    i->ifa_addr->sa_family = AF_INET;
    i->ifa_netmask = calloc(1, sizeof(struct sockaddr));
    i->ifa_netmask->sa_family = AF_INET;

    struct in_addr addr_buf;
    if (inet_pton(AF_INET, "127.0.0.1", &addr_buf) != 1) {
        shimc_api_freeifaddrs(i);
        errno = EADDRNOTAVAIL;
        return -1;
    }

    ((struct sockaddr_in*)i->ifa_addr)->sin_addr = addr_buf;

    if (inet_pton(AF_INET, "255.0.0.0", &addr_buf) != 1) {
        shimc_api_freeifaddrs(i);
        errno = EADDRNOTAVAIL;
        return -1;
    }

    ((struct sockaddr_in*)i->ifa_netmask)->sin_addr = addr_buf;

    /* also advertise the IPv6 loopback address */
    {
        struct ifaddrs* lo6 = calloc(1, sizeof(struct ifaddrs));
        lo6->ifa_flags = (IFF_UP | IFF_RUNNING | IFF_LOOPBACK);
        lo6->ifa_name = strdup("lo");

        lo6->ifa_addr = calloc(1, sizeof(struct sockaddr_in6));
        lo6->ifa_addr->sa_family = AF_INET6;
        lo6->ifa_netmask = calloc(1, sizeof(struct sockaddr_in6));
        lo6->ifa_netmask->sa_family = AF_INET6;

        struct in6_addr addr6_buf;
        struct in6_addr netmask6_128;
        if (inet_pton(AF_INET6, "::1", &addr6_buf) != 1 ||
            inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &netmask6_128) != 1) {
            shimc_api_freeifaddrs(lo6);
            shimc_api_freeifaddrs(i);
            errno = EADDRNOTAVAIL;
            return -1;
        }

        ((struct sockaddr_in6*)lo6->ifa_addr)->sin6_addr = addr6_buf;
        ((struct sockaddr_in6*)lo6->ifa_netmask)->sin6_addr = netmask6_128;

        i->ifa_next = lo6;
        /* subsequent entries are appended to lo6 */
        i = lo6;
    }

    /* a /24 netmask */
    struct in_addr netmask_24;
    if (inet_pton(AF_INET, "255.255.255.0", &netmask_24) != 1) {
        shimc_api_freeifaddrs(i);
        errno = EADDRNOTAVAIL;
        return -1;
    }

    /* get the hostname so we can use it to lookup the default net address */
    char hostname_buf[HOST_NAME_MAX] = {};
    if (gethostname(hostname_buf, HOST_NAME_MAX) == 0) {
        /* find the tail of the list */
        struct ifaddrs* tail = head;
        while (tail->ifa_next != NULL) {
            tail = tail->ifa_next;
        }

        struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
        struct addrinfo* host_ai;

        /* lookup the default net address for the host */
        if (getaddrinfo(hostname_buf, NULL, &hints, &host_ai) == 0) {
            struct ifaddrs* j = calloc(1, sizeof(struct ifaddrs));
            j->ifa_flags = (IFF_UP | IFF_RUNNING);
            j->ifa_name = strdup("eth0");

            j->ifa_addr = calloc(1, sizeof(struct sockaddr));
            memcpy(j->ifa_addr, host_ai->ai_addr, (unsigned long)host_ai->ai_addrlen);

            /* assign it a /24 netmask */
            /* some applications/libraries like libuv assume this will be non-null */
            j->ifa_netmask = calloc(1, sizeof(struct sockaddr));
            j->ifa_netmask->sa_family = AF_INET;
            ((struct sockaddr_in*)j->ifa_netmask)->sin_addr = netmask_24;

            tail->ifa_next = j;
            tail = j;

            freeaddrinfo(host_ai);
        }

        /* also advertise the host's IPv6 address */
        struct addrinfo hints6 = {.ai_family = AF_INET6, .ai_socktype = SOCK_STREAM};
        struct addrinfo* host_ai6;

        if (getaddrinfo(hostname_buf, NULL, &hints6, &host_ai6) == 0) {
            struct ifaddrs* j = calloc(1, sizeof(struct ifaddrs));
            j->ifa_flags = (IFF_UP | IFF_RUNNING);
            j->ifa_name = strdup("eth0");

            j->ifa_addr = calloc(1, sizeof(struct sockaddr_in6));
            memcpy(j->ifa_addr, host_ai6->ai_addr, (unsigned long)host_ai6->ai_addrlen);

            /* assign it a /64 netmask */
            j->ifa_netmask = calloc(1, sizeof(struct sockaddr));
            j->ifa_netmask->sa_family = AF_INET6;
            struct in6_addr netmask6_64;
            if (inet_pton(AF_INET6, "ffff:ffff:ffff:ffff::", &netmask6_64) == 1) {
                ((struct sockaddr_in6*)j->ifa_netmask)->sin6_addr = netmask6_64;
            }

            tail->ifa_next = j;

            freeaddrinfo(host_ai6);
        }
    }

    *ifap = head;
    return 0;
}

void shimc_api_freeifaddrs(struct ifaddrs* ifa) {
    struct ifaddrs* iter = ifa;
    while (iter != NULL) {
        struct ifaddrs* next = iter->ifa_next;
        if (iter->ifa_addr) {
            free(iter->ifa_addr);
        }
        if (iter->ifa_netmask) {
            free(iter->ifa_netmask);
        }
        if (iter->ifa_name) {
            free(iter->ifa_name);
        }
        free(iter);
        iter = next;
    }
}
