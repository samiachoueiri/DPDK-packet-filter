/*
 * Small two-port DPDK firewall demo.
 * Usage example:
 *   ./fw_demo <block-port>    # e.g. ./fw_demo 80
 *
 * Behavior:
 *  - port 0 = inside (LAN)
 *  - port 1 = outside (internet)
 *  - Packets received on outside are inspected for IPv4/TCP and
 *    dropped if TCP dst port == block-port.
 *  - All others are forwarded to the opposite port.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_spinlock.h>

#define RX_RING_SIZE 512
#define TX_RING_SIZE 512
#define NUM_MBUFS 4096
#define MBUF_CACHE_SIZE 128
#define BURST_SIZE 32

static volatile sig_atomic_t keep_running = 1;
static uint16_t block_port = 80; /* default */

struct stats {
    uint64_t total;
    uint64_t forwarded;
    uint64_t dropped_blocked;
    uint64_t dropped_malformed;
    uint64_t tx_failures;
} __rte_cache_aligned;
static struct stats st = {0};
static rte_spinlock_t st_lock = RTE_SPINLOCK_INITIALIZER;

/* signal handler */
static void handle_signal(int signum) { (void)signum; keep_running = 0; }

/* safe helpers */
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

/* atomic-ish stat update */
static inline void stat_inc(uint64_t *field, uint64_t v) {
    rte_spinlock_lock(&st_lock);
    *field += v;
    rte_spinlock_unlock(&st_lock);
}

/* initialize a single port */
static int init_port(uint16_t port, struct rte_mempool *mp) {
    struct rte_eth_conf conf = {0};
    struct rte_eth_dev_info dev_info;
    const uint16_t rxq = 1, txq = 1;
    int ret;

    /* query device capabilities first */
    rte_eth_dev_info_get(port, &dev_info);

    /* request TX checksum offloads if supported */
    uint64_t want_tx_offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
                                RTE_ETH_TX_OFFLOAD_TCP_CKSUM  |
                                RTE_ETH_TX_OFFLOAD_UDP_CKSUM;

    /* enable only supported offloads */
    conf.txmode.offloads = want_tx_offloads & dev_info.tx_offload_capa;

    /* keep RX offloads off (or enable if you want and device supports) */
    conf.rxmode.offloads = 0;
    conf.rxmode.max_lro_pkt_size = RTE_ETHER_MAX_LEN;

    ret = rte_eth_dev_configure(port, rxq, txq, &conf);
    if (ret < 0) {
        fprintf(stderr, "port %u configure failed: %s\n", port, rte_strerror(-ret));
        return ret;
    }

    ret = rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, mp);
    if (ret < 0) { fprintf(stderr,"rxq setup failed\n"); return ret; }

    ret = rte_eth_tx_queue_setup(port, 0, TX_RING_SIZE, rte_eth_dev_socket_id(port), NULL);
    if (ret < 0) { fprintf(stderr,"txq setup failed\n"); return ret; }

    ret = rte_eth_dev_start(port);
    if (ret < 0) { fprintf(stderr,"dev start failed\n"); return ret; }

    rte_eth_promiscuous_enable(port);

    /* optional: print which offloads were enabled for visibility */
    // if (conf.txmode.offloads) {
    //     printf("port %u enabled tx offloads: 0x%016" PRIx64 "\n", port, conf.txmode.offloads);
    // } else {
    //     printf("port %u: no tx checksum offloads enabled (not supported by NIC)\n", port);
    // }

    return 0;
}

/* process single packet: return 0 => forward, -1 => drop */
static int inspect_packet(struct rte_mbuf *m, uint16_t in_port, uint16_t outside_port) {
    stat_inc(&st.total, 1);

    struct rte_ether_hdr *eth = eth_hdr(m);
    if (!eth) { stat_inc(&st.dropped_malformed, 1); return -1; }

    /* only apply rules for packets coming from outside */
    if (in_port != outside_port) return 0;

    struct rte_ipv4_hdr *ip = ipv4_hdr(m, eth);
    if (!ip) return 0; /* non-IPv4: allow through (demo) */

    if ((ip->version_ihl >> 4) != 4) { stat_inc(&st.dropped_malformed, 1); return -1; }

    struct rte_tcp_hdr *tcp = tcp_hdr(m, ip);
    if (!tcp) return 0;

    uint16_t dst = rte_be_to_cpu_16(tcp->dst_port);
    if (dst == block_port) {
        stat_inc(&st.dropped_blocked, 1);
        return -1;
    }
    return 0;
}

/* forward burst from in_port to out_port */
static void forward_burst(struct rte_mbuf **pkts, uint16_t nb_pkts, uint16_t out_port) {
    if (nb_pkts == 0) return;
    uint16_t sent = rte_eth_tx_burst(out_port, 0, pkts, nb_pkts);
    if (sent < nb_pkts) {
        for (uint16_t i = sent; i < nb_pkts; ++i) {
            rte_pktmbuf_free(pkts[i]);
            stat_inc(&st.tx_failures, 1);
        }
    }
    stat_inc(&st.forwarded, sent);
}

/* main loop: poll both ports, inspect outside traffic only */
static void run_loop(uint16_t inside_port, uint16_t outside_port) {
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t in_port, out_port;
    while (keep_running) {
        /* poll outside (port 1) first, then inside (port 0) */
        for (int p = 0; p < 2; ++p) {
            in_port = (p == 0) ? outside_port : inside_port;
            out_port = (in_port == inside_port) ? outside_port : inside_port;

            uint16_t nb_rx = rte_eth_rx_burst(in_port, 0, bufs, BURST_SIZE);
            if (nb_rx == 0) continue;

            uint16_t to_forward = 0;
            for (uint16_t i = 0; i < nb_rx; ++i) {
                struct rte_mbuf *m = bufs[i];
                if (inspect_packet(m, in_port, outside_port) == 0) {
                    bufs[to_forward++] = m; /* keep */
                } else {
                    rte_pktmbuf_free(m);
                }
            }
            if (to_forward) forward_burst(bufs, to_forward, out_port);
        }
    }
}

/* simple stats printer */
static void print_stats(void) {
    rte_spinlock_lock(&st_lock);
    printf("\n--- stats ---\n");
    printf("total: %"PRIu64"\n", st.total);
    printf("forwarded: %"PRIu64"\n", st.forwarded);
    printf("dropped_blocked: %"PRIu64"\n", st.dropped_blocked);
    printf("dropped_malformed: %"PRIu64"\n", st.dropped_malformed);
    printf("tx_failures: %"PRIu64"\n", st.tx_failures);
    printf("--------------\n");
    rte_spinlock_unlock(&st_lock);
}

int main(int argc, char **argv) {
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");
    argc -= ret; argv += ret;

    if (argc > 1) {
        char *end = NULL;
        long v = strtol(argv[1], &end, 10);
        if (end && *end == '\0' && v > 0 && v <= 65535) block_port = (uint16_t)v;
        else fprintf(stderr, "Invalid block port, using %u\n", block_port);
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 2) rte_exit(EXIT_FAILURE, "Need at least two ports (found %u)\n", nb_ports);

    struct rte_mempool *mp = rte_pktmbuf_pool_create("MP", NUM_MBUFS * nb_ports,
                                                     MBUF_CACHE_SIZE, 0,
                                                     RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mp) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* ports: 0 = inside, 1 = outside (demo) */
    if (init_port(0, mp) != 0) rte_exit(EXIT_FAILURE, "init port 0 failed\n");
    if (init_port(1, mp) != 0) rte_exit(EXIT_FAILURE, "init port 1 failed\n");

    printf("Demo firewall: inside=0 outside=1 block_port=%u\n", block_port);

    run_loop(0, 1);

    /* cleanup */
    print_stats();
    rte_eth_dev_stop(0); rte_eth_dev_stop(1);
    rte_eth_dev_close(0); rte_eth_dev_close(1);
    rte_mempool_free(mp);
    rte_eal_cleanup();
    printf("Shutdown complete\n");
    return 0;
}
