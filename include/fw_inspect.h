#ifndef FW_INSPECT_H
#define FW_INSPECT_H

#include <rte_mbuf.h>
#include "fw_ctx.h"

int fw_inspect_init(struct fw_ctx *ctx, uint16_t block_port);
/* returns 0 to forward, -1 to drop */
int fw_inspect_packet(struct fw_ctx *ctx, struct rte_mbuf *m, uint16_t in_port);

#endif /* FW_INSPECT_H */
