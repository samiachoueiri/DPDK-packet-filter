#ifndef FW_CTX_H
#define FW_CTX_H

#include <stdint.h>

struct fw_stats;
struct fw_net_ops;

struct fw_config {
    uint16_t inside_port;
    uint16_t outside_port;
    uint16_t block_port;
};

struct fw_ctx {
    struct fw_config cfg;
    struct fw_stats *stats;
    struct fw_net_ops *net;
    void *user; /* opaque pointer for net-specific state */
};

int fw_ctx_init(struct fw_ctx *ctx);
int fw_ctx_shutdown(struct fw_ctx *ctx);

#endif /* FW_CTX_H */
