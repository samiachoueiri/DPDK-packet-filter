/* minimal_port.c - DPDK port configuration wrapper for firewall */
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "minimal_port.h"

int port_probe_and_config(uint16_t port_id, struct rte_mempool *mbuf_pool)
{
    if (!rte_eth_dev_is_valid_port(port_id)) {
        fprintf(stderr, "port_probe_and_config: invalid port %u\n", port_id);
        return -1;
    }
    if (mbuf_pool == NULL) {
        fprintf(stderr, "port_probe_and_config: null mbuf_pool\n");
        return -1;
    }

    struct rte_eth_conf port_conf = {
        .rxmode = {
            .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
            .mq_mode = RTE_ETH_MQ_RX_NONE,
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        }
    };

    int ret = rte_eth_dev_configure(port_id, DEFAULT_RX_RINGS, 
                                   DEFAULT_TX_RINGS, &port_conf);
    if (ret != 0) {
        fprintf(stderr, "rte_eth_dev_configure(port=%u) failed: %s\n", 
                port_id, rte_strerror(-ret));
        return ret;
    }

    /* set up RX queues */
    for (uint16_t q = 0; q < DEFAULT_RX_RINGS; ++q) {
        ret = rte_eth_rx_queue_setup(port_id, q, DEFAULT_RX_DESC,
                                     rte_eth_dev_socket_id(port_id), 
                                     NULL, mbuf_pool);
        if (ret < 0) {
            fprintf(stderr, "rte_eth_rx_queue_setup(port=%u,q=%u) failed: %s\n",
                    port_id, q, rte_strerror(-ret));
            return ret;
        }
    }

    /* set up TX queues */
    for (uint16_t q = 0; q < DEFAULT_TX_RINGS; ++q) {
        ret = rte_eth_tx_queue_setup(port_id, q, DEFAULT_TX_DESC,
                                     rte_eth_dev_socket_id(port_id), NULL);
        if (ret < 0) {
            fprintf(stderr, "rte_eth_tx_queue_setup(port=%u,q=%u) failed: %s\n",
                    port_id, q, rte_strerror(-ret));
            return ret;
        }
    }

    /* start device */
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        fprintf(stderr, "rte_eth_dev_start(%u) failed: %s\n", 
                port_id, rte_strerror(-ret));
        return ret;
    }

    /* enable promiscuous mode for demo */
    rte_eth_promiscuous_enable(port_id);

    printf("Port %u configured and started\n", port_id);
    return 0;
}

void port_stop_and_close(uint16_t port_id)
{
    if (!rte_eth_dev_is_valid_port(port_id)) {
        return;
    }
    
    printf("Stopping port %u\n", port_id);
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
}

struct rte_mempool *create_mempool(const char *name, unsigned num_mbufs,
                                   unsigned cache_size, int socket_id)
{
    struct rte_mempool *mp = rte_pktmbuf_pool_create(name,
                                                     num_mbufs,
                                                     cache_size,
                                                     0,
                                                     RTE_MBUF_DEFAULT_BUF_SIZE,
                                                     socket_id);
    if (!mp) {
        fprintf(stderr, "Failed to create mempool '%s': %s\n",
                name, rte_strerror(rte_errno));
    }
    return mp;
}