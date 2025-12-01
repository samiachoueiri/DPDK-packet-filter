#include "fw_ctx.h"
#include "fw_stats.h"
#include <stdlib.h>
#include <stdio.h>

int fw_ctx_init(struct fw_ctx *ctx) {
    if (!ctx) return -1;
    
    /* Initialize stats */
    ctx->stats = fw_stats_create();
    if (!ctx->stats) return -1;
    
    /* Set default configuration */
    ctx->cfg.inside_port = 0;
    ctx->cfg.outside_port = 1;
    ctx->cfg.block_port = 80;
    
    return 0;
}

int fw_ctx_shutdown(struct fw_ctx *ctx) {
    if (!ctx) return -1;
    
    /* Print final stats */
    fw_stats_print(ctx->stats);
    
    /* Clean up stats */
    fw_stats_destroy(ctx->stats);
    ctx->stats = NULL;
    
    return 0;
}