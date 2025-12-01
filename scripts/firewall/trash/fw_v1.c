/*
 * Usage: ./build/fw 80 -l 0 -n 4 -a 0000:07:00.0 -- -p 0x1
 sudo ./build/fw 80 -l 0 -n 4 -a 0000:08:00.0 -- -p 0x1
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_atomic.h>


#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8192
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static volatile uint32_t keep_running = 1;
static uint16_t block_port = 80; /* default blocked TCP dst port */

/* Statistics */
struct firewall_stats {
    uint64_t total_packets;
    uint64_t dropped_tcp_port;
    uint64_t dropped_malformed;
    uint64_t forwarded;
    uint64_t errors;
};

static struct firewall_stats stats = {0};
static rte_spinlock_t stats_lock = RTE_SPINLOCK_INITIALIZER;

static void
signal_handler(int signum)
{
    (void)signum;
    keep_running = 0;
}

/* Safe packet header access functions */
static inline struct rte_ether_hdr *
get_eth_hdr(struct rte_mbuf *m)
{
    if (rte_pktmbuf_data_len(m) < sizeof(struct rte_ether_hdr))
        return NULL;
    return rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
}

static inline struct rte_ipv4_hdr *
get_ipv4_hdr(struct rte_ether_hdr *eth, struct rte_mbuf *m)
{
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);
    if (ether_type != RTE_ETHER_TYPE_IPV4)
        return NULL;
    
    if (rte_pktmbuf_data_len(m) < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr))
        return NULL;
    
    return (struct rte_ipv4_hdr *)((char *)eth + sizeof(struct rte_ether_hdr));
}

static inline struct rte_tcp_hdr *
get_tcp_hdr(struct rte_ipv4_hdr *ip, struct rte_mbuf *m)
{
    if (ip->next_proto_id != IPPROTO_TCP)
        return NULL;
    
    uint16_t ip_hdr_len = (ip->ihl * 4);
    if (ip_hdr_len < sizeof(struct rte_ipv4_hdr) || 
        ip_hdr_len > (rte_pktmbuf_data_len(m) - sizeof(struct rte_ether_hdr)))
        return NULL;
    
    uint16_t total_len = rte_be_to_cpu_16(ip->total_length);
    if (total_len < ip_hdr_len + sizeof(struct rte_tcp_hdr))
        return NULL;
    
    if (rte_pktmbuf_data_len(m) < sizeof(struct rte_ether_hdr) + ip_hdr_len + sizeof(struct rte_tcp_hdr))
        return NULL;
    
    return (struct rte_tcp_hdr *)((char *)ip + ip_hdr_len);
}

/* Thread-safe statistics update */
static inline void
update_stat(uint64_t *stat, uint64_t value)
{
    rte_spinlock_lock(&stats_lock);
    *stat += value;
    rte_spinlock_unlock(&stats_lock);
}

/* Print statistics periodically */
static void
print_stats(void)
{
    rte_spinlock_lock(&stats_lock);
    printf("\n=== Firewall Statistics ===\n");
    printf("Total packets: %"PRIu64"\n", stats.total_packets);
    printf("Forwarded: %"PRIu64"\n", stats.forwarded);
    printf("Dropped (TCP port): %"PRIu64"\n", stats.dropped_tcp_port);
    printf("Dropped (malformed): %"PRIu64"\n", stats.dropped_malformed);
    printf("Errors: %"PRIu64"\n", stats.errors);
    printf("===========================\n");
    rte_spinlock_unlock(&stats_lock);
}

/* Simple port init with checksum offload support */
static int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mtu = RTE_ETHER_MAX_LEN - RTE_ETHER_CRC_LEN,
            .offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM
        },
        .txmode = {
            .offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
                       RTE_ETH_TX_OFFLOAD_TCP_CKSUM
        }
    };
    
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t q;
    int ret;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    struct rte_eth_dev_info dev_info;

    ret = rte_eth_dev_info_get(port, &dev_info);
    if (ret != 0) {
        printf("Error getting device info for port %u: %s\n", port, rte_strerror(-ret));
        return ret;
    }

    /* Adjust offloads based on device capabilities */
    port_conf.rxmode.offloads &= dev_info.rx_offload_capa;
    port_conf.txmode.offloads &= dev_info.tx_offload_capa;

    ret = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (ret < 0) {
        printf("Error configuring port %u: %s\n", port, rte_strerror(-ret));
        return ret;
    }

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (ret < 0) {
        printf("Error adjusting descriptors for port %u: %s\n", port, rte_strerror(-ret));
        return ret;
    }

    for (q = 0; q < rx_rings; q++) {
        ret = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (ret < 0) {
            printf("Error setting up RX queue %u: %s\n", q, rte_strerror(-ret));
            return ret;
        }
    }
    for (q = 0; q < tx_rings; q++) {
        ret = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), NULL);
        if (ret < 0) {
            printf("Error setting up TX queue %u: %s\n", q, rte_strerror(-ret));
            return ret;
        }
    }

    ret = rte_eth_dev_start(port);
    if (ret < 0) {
        printf("Error starting port %u: %s\n", port, rte_strerror(-ret));
        return ret;
    }

    /* Enable promiscuous mode for security monitoring */
    rte_eth_promiscuous_enable(port);
    
    /* Print port information */
    struct rte_eth_link link;
    rte_eth_link_get(port, &link);
    printf("Port %u started: %s, %u Gbps\n", 
           port, 
           link.link_status ? "UP" : "DOWN",
           link.link_speed / 1000);
    
    return 0;
}

/* Process a single packet with full validation */
static int
process_packet(struct rte_mbuf *m)
{
    update_stat(&stats.total_packets, 1);

    /* Validate Ethernet header */
    struct rte_ether_hdr *eth = get_eth_hdr(m);
    if (!eth) {
        update_stat(&stats.dropped_malformed, 1);
        return -1;
    }

    /* Validate IPv4 header */
    struct rte_ipv4_hdr *ip = get_ipv4_hdr(eth, m);
    if (!ip) {
        /* Not IPv4 or malformed - forward anyway (could be ARP, IPv6, etc.) */
        return 0;
    }

    /* Basic IP header validation */
    if ((ip->version_ihl >> 4) != 4) {
        update_stat(&stats.dropped_malformed, 1);
        return -1;
    }

    /* Validate IP header length */
    uint8_t ihl = ip->version_ihl & 0x0F;
    if (ihl < 5) {
        update_stat(&stats.dropped_malformed, 1);
        return -1;
    }

    /* Validate TCP header for TCP packets */
    struct rte_tcp_hdr *tcp = get_tcp_hdr(ip, m);
    if (tcp) {
        uint16_t dst_port = rte_be_to_cpu_16(tcp->dst_port);
        if (dst_port == block_port) {
            update_stat(&stats.dropped_tcp_port, 1);
            return -1;
        }
    }

    return 0;
}

/* Simple per-core main: RX burst, check TCP dst port, drop if match, else TX. */
static int
lcore_main(__attribute__((unused)) void *arg)
{
    const uint16_t port = 0; /* single-port example */
    struct rte_mbuf *bufs[BURST_SIZE];
    uint64_t last_stat_print = 0;
    uint64_t cycles_per_sec = rte_get_timer_hz();

    while (keep_running) {
        const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
        if (nb_rx == 0) {
            /* Print stats every 5 seconds */
            uint64_t now = rte_get_timer_cycles();
            if (now - last_stat_print > (5 * cycles_per_sec)) {
                print_stats();
                last_stat_print = now;
            }
            rte_delay_us(1); /* Small delay to reduce CPU usage */
            continue;
        }

        uint16_t nb_tx = 0;
        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *m = bufs[i];

            if (process_packet(m) == 0) {
                /* Packet passed all checks - forward */
                bufs[nb_tx++] = m;
                update_stat(&stats.forwarded, 1);
            } else {
                /* Packet dropped */
                rte_pktmbuf_free(m);
            }
        }

        if (nb_tx > 0) {
            const uint16_t sent = rte_eth_tx_burst(port, 0, bufs, nb_tx);
            if (sent < nb_tx) {
                /* Free unsent packets (backpressure) */
                for (uint16_t j = sent; j < nb_tx; j++) {
                    rte_pktmbuf_free(bufs[j]);
                    update_stat(&stats.errors, 1);
                }
            }
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "EAL initialization failed: %s\n", rte_strerror(-ret));
    }

    argc -= ret;
    argv += ret;

    /* Parse command line arguments */
    if (argc > 1) {
        char *endptr;
        long v = strtol(argv[1], &endptr, 10);
        if (endptr != argv[1] && *endptr == '\0' && v > 0 && v <= 65535) {
            block_port = (uint16_t)v;
        } else {
            fprintf(stderr, "Invalid port number: %s. Using default: %u\n", argv[1], block_port);
        }
    }
    printf("Blocking TCP dst port: %u\n", block_port);

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Check available ports */
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");
    }
    
    printf("Available ports: %u\n", nb_ports);

    /* Create memory pool */
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
                                                           NUM_MBUFS * nb_ports,
                                                           MBUF_CACHE_SIZE, 0,
                                                           RTE_MBUF_DEFAULT_BUF_SIZE,
                                                           rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }

    /* Initialize first port only (simple single-port firewall) */
    if (port_init(0, mbuf_pool) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot init port 0\n");
    }

    printf("Firewall started. Press Ctrl+C to stop.\n");

    /* Launch worker on main lcore */
    lcore_main(NULL);

    /* Cleanup */
    printf("\nShutting down firewall...\n");
    print_stats();
    
    rte_eth_dev_stop(0);
    rte_eth_dev_close(0);
    rte_mempool_free(mbuf_pool);
    rte_eal_cleanup();
    
    printf("Firewall stopped successfully.\n");
    return 0;
}