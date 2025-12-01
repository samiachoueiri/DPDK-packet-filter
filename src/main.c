/* Minimal wiring example sketch. This file is a scaffold and omits full DPDK init/error handling. */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <rte_eal.h>
#include "fw_ctx.h"
#include "fw_stats.h"
#include "fw_inspect.h"

#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_errno.h>
#include <unistd.h> /* for sleep */

#define NUM_MBUFS 8192
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

int fw_ctx_init(struct fw_ctx *ctx) {
    if (!ctx) return -1;
    ctx->stats = fw_stats_create();
    if (!ctx->stats) return -1;
    ctx->cfg.inside_port = 0;
    ctx->cfg.outside_port = 1;
    ctx->cfg.block_port = 80;
    return 0;
}

int fw_ctx_shutdown(struct fw_ctx *ctx) {
    if (!ctx) return -1;
    fw_stats_print(ctx->stats);
    fw_stats_destroy(ctx->stats);
    return 0;
}

static volatile sig_atomic_t keep_running = 1;
static void handle_signal(int signum) { (void)signum; keep_running = 0; }

/* This is a very small demo loop; it does not include mempool/port setup. */
void run_loop_demo(struct fw_ctx *ctx) {
  
    while (keep_running) {
        /* In real code: rx burst, for each pkt call fw_inspect_packet, forward or free */
        break;
    }
}

int main(int argc, char **argv) {
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");
    argc -= ret; argv += ret;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    struct fw_ctx ctx;
    if (fw_ctx_init(&ctx) != 0) rte_exit(EXIT_FAILURE, "ctx init failed\n");
    if (fw_inspect_init(&ctx, ctx.cfg.block_port) != 0) rte_exit(EXIT_FAILURE, "inspect init failed\n");

    run_loop_demo(&ctx);

    fw_ctx_shutdown(&ctx);
    return 0;
}
