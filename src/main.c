/* Minimal wiring example with DPDK port setup */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_errno.h>
#include <unistd.h>
#include "fw_ctx.h"
#include "fw_stats.h"
#include "fw_inspect.h"
#include "port_config.h"

/* Configuration */
#define NUM_MBUFS 8192
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

/* Global state */
static volatile sig_atomic_t keep_running = 1;
static struct rte_mempool *mbuf_pool = NULL;

/* Signal handler */
static void handle_signal(int signum) 
{ 
    (void)signum; 
    keep_running = 0; 
}

/* Process a burst of packets - helper function */
static void process_packet_burst(struct fw_ctx *ctx, 
                                 struct rte_mbuf **burst, 
                                 uint16_t nb_pkts,
                                 uint16_t src_port, 
                                 uint16_t dst_port)
{
    struct rte_mbuf *tx_burst[BURST_SIZE];
    uint16_t tx_count = 0;
    uint16_t nb_tx;
    
    for (int i = 0; i < nb_pkts; i++) {
        struct rte_mbuf *m = burst[i];
        
        /* Inspect packet - only need source port (where packet came from) */
        int decision = fw_inspect_packet(ctx, m, src_port);
        
        /* Note: Your fw_inspect_packet already increments total counter!
           So we don't need to call fw_stats_inc_total here */
        
        if (decision == 0) {
            /* Forward packet (fw_inspect_packet returned 0) */
            tx_burst[tx_count++] = m;
            /* Note: fw_inspect_packet doesn't increment forwarded counter,
               so we need to do it here */
            fw_stats_inc_forwarded(ctx->stats, 1);
        } else {
            /* Block/drop packet (fw_inspect_packet returned -1) */
            rte_pktmbuf_free(m);
            /* Note: fw_inspect_packet already increments blocked/malformed counters
               based on why it was dropped, so we don't need to do it here */
        }
        
        /* Transmit if burst is full or this is the last packet */
        if (tx_count == BURST_SIZE || (i == nb_pkts - 1 && tx_count > 0)) {
            nb_tx = rte_eth_tx_burst(dst_port, 0, tx_burst, tx_count);
            
            /* Free any untransmitted packets */
            for (int j = nb_tx; j < tx_count; j++) {
                rte_pktmbuf_free(tx_burst[j]);
                fw_stats_inc_tx_failures(ctx->stats, 1);
            }
            
            tx_count = 0;
        }
    }
}

/* Packet processing loop */
void run_loop_demo(struct fw_ctx *ctx) 
{
    struct rte_mbuf *rx_burst[BURST_SIZE];
    uint16_t nb_rx;
    uint16_t inside_port = ctx->cfg.inside_port;
    uint16_t outside_port = ctx->cfg.outside_port;
    
    printf("Starting packet loop (ports %u <-> %u)...\n", 
           inside_port, outside_port);
    
    uint64_t last_stats_print = 0;
    const uint64_t STATS_INTERVAL = 5e8; /* 5 seconds in nanoseconds */
    
    while (keep_running) {
        uint64_t current_tsc = rte_rdtsc();
        
        /* Print stats every 5 seconds */
        if (current_tsc - last_stats_print > STATS_INTERVAL) {
            fw_stats_print(ctx->stats);
            last_stats_print = current_tsc;
        }
        
        /* Process inside -> outside traffic */
        nb_rx = rte_eth_rx_burst(inside_port, 0, rx_burst, BURST_SIZE);
        if (nb_rx > 0) {
            process_packet_burst(ctx, rx_burst, nb_rx, 
                                inside_port, outside_port);
        }
        
        /* Process outside -> inside traffic */
        nb_rx = rte_eth_rx_burst(outside_port, 0, rx_burst, BURST_SIZE);
        if (nb_rx > 0) {
            process_packet_burst(ctx, rx_burst, nb_rx, 
                                outside_port, inside_port);
        }
        
        /* Small pause if no packets to prevent CPU spinning */
        if (nb_rx == 0) {
            usleep(10); /* 10 microsecond sleep */
        }
    }
    
    printf("Packet loop stopped\n");
}

int main(int argc, char **argv) 
{
    /* Parse command line arguments - only block port from command line */
    uint16_t block_port = 80;  /* Default */
    char *eal_args[argc + 2];  /* For passing to DPDK EAL */
    int eal_argc = 0;
    
    /* Separate DPDK EAL args from our args */
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--block-port") == 0 && i + 1 < argc) {
            block_port = atoi(argv[++i]);
        } else {
            /* Pass through to DPDK EAL */
            eal_args[eal_argc++] = argv[i];
        }
    }
    eal_args[eal_argc] = NULL;
    
    /* Initialize DPDK EAL */
    int ret = rte_eal_init(eal_argc, eal_args);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "EAL init failed\n");
    }
    
    /* Set up signal handlers */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    /* Create mempool */
    mbuf_pool = create_mempool("FW_MBUF_POOL", NUM_MBUFS, 
                              MBUF_CACHE_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        rte_exit(EXIT_FAILURE, "Mempool creation failed\n");
    }
    
    /* Initialize firewall context using YOUR function */
    struct fw_ctx ctx;
    if (fw_ctx_init(&ctx) != 0) {
        rte_exit(EXIT_FAILURE, "Context init failed\n");
    }
    
    /* Override ONLY the block port from command line */
    ctx.cfg.block_port = block_port;
    
    printf("Firewall configuration:\n");
    printf("  Inside port:  %u (from fw_ctx_init)\n", ctx.cfg.inside_port);
    printf("  Outside port: %u (from fw_ctx_init)\n", ctx.cfg.outside_port);
    printf("  Block port:   %u (command line)\n", ctx.cfg.block_port);
    
    /* Check available ports */
    uint16_t port_count = rte_eth_dev_count_avail();
    printf("Available DPDK ports: %u\n", port_count);
    
    if (port_count < 2) {
        rte_exit(EXIT_FAILURE, "Need at least 2 ports, found %u\n", port_count);
    }
    
    /* Validate configured ports */
    if (!rte_eth_dev_is_valid_port(ctx.cfg.inside_port)) {
        rte_exit(EXIT_FAILURE, "Invalid inside port: %u\n", ctx.cfg.inside_port);
    }
    
    if (!rte_eth_dev_is_valid_port(ctx.cfg.outside_port)) {
        rte_exit(EXIT_FAILURE, "Invalid outside port: %u\n", ctx.cfg.outside_port);
    }
    
    /* Configure ports using port_config functions */
    printf("Configuring inside port %u...\n", ctx.cfg.inside_port);
    if (port_probe_and_config(ctx.cfg.inside_port, mbuf_pool) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to configure inside port %u\n", 
                ctx.cfg.inside_port);
    }
    
    printf("Configuring outside port %u...\n", ctx.cfg.outside_port);
    if (port_probe_and_config(ctx.cfg.outside_port, mbuf_pool) != 0) {
        port_stop_and_close(ctx.cfg.inside_port);
        rte_exit(EXIT_FAILURE, "Failed to configure outside port %u\n", 
                ctx.cfg.outside_port);
    }
    
    /* Initialize packet inspection */
    if (fw_inspect_init(&ctx, ctx.cfg.block_port) != 0) {
        port_stop_and_close(ctx.cfg.inside_port);
        port_stop_and_close(ctx.cfg.outside_port);
        rte_exit(EXIT_FAILURE, "Inspect init failed\n");
    }
    
    /* Run packet processing loop */
    run_loop_demo(&ctx);
    
    /* Cleanup */
    printf("Shutting down...\n");
    port_stop_and_close(ctx.cfg.inside_port);
    port_stop_and_close(ctx.cfg.outside_port);
    
    fw_ctx_shutdown(&ctx);
    
    /* Note: mempool is automatically freed by DPDK on exit */
    printf("Firewall shutdown complete\n");
    return 0;
}