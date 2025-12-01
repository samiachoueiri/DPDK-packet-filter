#include "fw_packet.h"
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <stddef.h>

static inline struct rte_ether_hdr *eth_hdr(struct rte_mbuf *m) {
    if (rte_pktmbuf_pkt_len(m) < sizeof(struct rte_ether_hdr)) return NULL;
    return rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
}

static inline struct rte_ipv4_hdr *ipv4_hdr(struct rte_mbuf *m, struct rte_ether_hdr *eth) {
    uint16_t eth_type = rte_be_to_cpu_16(eth->ether_type);
    if (eth_type != RTE_ETHER_TYPE_IPV4) return NULL;
    uint8_t *p = (uint8_t *)eth + sizeof(*eth);
    size_t remain = rte_pktmbuf_pkt_len(m) - sizeof(*eth);
    if (remain < sizeof(struct rte_ipv4_hdr)) return NULL;
    return (struct rte_ipv4_hdr *)p;
}

static inline struct rte_tcp_hdr *tcp_hdr(struct rte_mbuf *m, struct rte_ipv4_hdr *ip) {
    if (!ip) return NULL;
    if (ip->next_proto_id != IPPROTO_TCP) return NULL;
    uint8_t ihl = (ip->version_ihl & 0x0f) * 4;
    if (ihl < sizeof(struct rte_ipv4_hdr)) return NULL;
    size_t ip_payload_len = rte_be_to_cpu_16(ip->total_length) - ihl;
    if (ip_payload_len < sizeof(struct rte_tcp_hdr)) return NULL;
    uint8_t *p = (uint8_t *)ip + ihl;
    return (struct rte_tcp_hdr *)p;
}

int packet_view_init(struct packet_view *pv, struct rte_mbuf *m) {
    if (!pv || !m) return -1;
    pv->mbuf = m;
    pv->eth = eth_hdr(m);
    if (!pv->eth) return -1;
    pv->ip = ipv4_hdr(m, pv->eth);
    pv->is_ipv4 = (pv->ip != NULL) && ((pv->ip->version_ihl >> 4) == 4);
    pv->tcp = pv->is_ipv4 ? tcp_hdr(m, pv->ip) : NULL;
    pv->is_tcp = (pv->tcp != NULL);
    return 0;
}
