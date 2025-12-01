/* minimal_port.c - DPDK port configuration wrapper for firewall */
#ifndef MINIMAL_PORT_H
#define MINIMAL_PORT_H

#include <rte_ethdev.h>
#include <rte_mempool.h>

/* Tunable configuration */
enum {
    DEFAULT_RX_DESC = 128,
    DEFAULT_TX_DESC = 512,
    DEFAULT_RX_RINGS = 1,
    DEFAULT_TX_RINGS = 1,
};

/**
 * Configure and start a DPDK port
 * @param port_id DPDK port ID to configure
 * @param mbuf_pool Mempool for RX buffers
 * @return 0 on success, negative on failure
 */
int port_probe_and_config(uint16_t port_id, struct rte_mempool *mbuf_pool);

/**
 * Stop and close a DPDK port
 * @param port_id DPDK port ID to clean up
 */
void port_stop_and_close(uint16_t port_id);

/**
 * Create mempool for packet buffers
 * @param name Mempool name
 * @param num_mbufs Number of mbufs in pool
 * @param cache_size Cache size
 * @param socket_id NUMA socket ID
 * @return Pointer to mempool or NULL on error
 */
struct rte_mempool *create_mempool(const char *name, unsigned num_mbufs,
                                   unsigned cache_size, int socket_id);

#endif /* MINIMAL_PORT_H */