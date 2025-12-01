#ifndef FW_STATS_H
#define FW_STATS_H

#include <stdint.h>

struct fw_stats;

struct fw_stats *fw_stats_create(void);
void fw_stats_destroy(struct fw_stats *s);
void fw_stats_inc_total(struct fw_stats *s, uint64_t v);
void fw_stats_inc_forwarded(struct fw_stats *s, uint64_t v);
void fw_stats_inc_dropped_blocked(struct fw_stats *s, uint64_t v);
void fw_stats_inc_dropped_malformed(struct fw_stats *s, uint64_t v);
void fw_stats_inc_tx_failures(struct fw_stats *s, uint64_t v);
void fw_stats_print(struct fw_stats *s);

#endif /* FW_STATS_H */
