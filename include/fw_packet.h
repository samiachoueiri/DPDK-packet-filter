#ifndef FW_PACKET_H
#define FW_PACKET_H

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

struct packet_view {
    struct rte_mbuf *mbuf;
    struct rte_ether_hdr *eth;
    struct rte_ipv4_hdr *ip;
    struct rte_tcp_hdr *tcp;
    int is_ipv4;
    int is_tcp;
};

int packet_view_init(struct packet_view *pv, struct rte_mbuf *m);

#endif /* FW_PACKET_H */
