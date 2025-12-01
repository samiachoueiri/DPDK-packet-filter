#include "fw_stats.h"
#include <stdlib.h>
#include <stdio.h>
#include <rte_spinlock.h>
#include <inttypes.h>

struct fw_stats {
    uint64_t total;
    uint64_t forwarded;
    uint64_t dropped_blocked;
    uint64_t dropped_malformed;
    uint64_t tx_failures;
    rte_spinlock_t lock;
};

struct fw_stats *fw_stats_create(void) {
    struct fw_stats *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->lock = RTE_SPINLOCK_INITIALIZER;
    return s;
}

void fw_stats_destroy(struct fw_stats *s) {
    if (!s) return;
    free(s);
}

static inline void _inc(struct fw_stats *s, uint64_t *field, uint64_t v) {
    rte_spinlock_lock(&s->lock);
    *field += v;
    rte_spinlock_unlock(&s->lock);
}

void fw_stats_inc_total(struct fw_stats *s, uint64_t v) { _inc(s, &s->total, v); }
void fw_stats_inc_forwarded(struct fw_stats *s, uint64_t v) { _inc(s, &s->forwarded, v); }
void fw_stats_inc_dropped_blocked(struct fw_stats *s, uint64_t v) { _inc(s, &s->dropped_blocked, v); }
void fw_stats_inc_dropped_malformed(struct fw_stats *s, uint64_t v) { _inc(s, &s->dropped_malformed, v); }
void fw_stats_inc_tx_failures(struct fw_stats *s, uint64_t v) { _inc(s, &s->tx_failures, v); }

void fw_stats_print(struct fw_stats *s) {
    rte_spinlock_lock(&s->lock);
    printf("=== stats ===\n");
    printf("total: %"PRIu64"\n", s->total);
    printf("forwarded: %"PRIu64"\n", s->forwarded);
    printf("dropped_blocked: %"PRIu64"\n", s->dropped_blocked);
    printf("dropped_malformed: %"PRIu64"\n", s->dropped_malformed);
    printf("tx_failures: %"PRIu64"\n", s->tx_failures);
    printf("============\n");
    rte_spinlock_unlock(&s->lock);
}
