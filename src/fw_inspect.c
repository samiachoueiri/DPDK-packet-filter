#include "fw_inspect.h"
#include "fw_packet.h"
#include "fw_stats.h"
#include <rte_byteorder.h>

int fw_inspect_init(struct fw_ctx *ctx, uint16_t block_port) {
    if (!ctx) return -1;
    ctx->cfg.block_port = block_port;
    return 0;
}

int fw_inspect_packet(struct fw_ctx *ctx, struct rte_mbuf *m, uint16_t in_port) {
    fw_stats_inc_total(ctx->stats, 1);
    if (in_port != ctx->cfg.outside_port) return 0; /* only inspect outside */
    struct packet_view pv;
    if (packet_view_init(&pv, m) < 0) { fw_stats_inc_dropped_malformed(ctx->stats, 1); return -1; }
    if (!pv.is_ipv4) return 0;
    if (!pv.is_tcp) return 0;
    uint16_t dst = rte_be_to_cpu_16(pv.tcp->dst_port);
    if (dst == ctx->cfg.block_port) { fw_stats_inc_dropped_blocked(ctx->stats, 1); return -1; }
    return 0;
}
