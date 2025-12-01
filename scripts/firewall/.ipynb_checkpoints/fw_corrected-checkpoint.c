/*
 * Splint-friendly firewall demo
 *
 * Notes:
 *  - allocate_packet_buffer is annotated with  to indicate it may return NULL.
 *  - All variables are declared at function starts (C89 style) to avoid Splint parse errors.
 *  - Defensive null checks and proper initialization added.
 *  - Use simple Splint annotations; remove -nullret if you prefer to annotate instead.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* constants */
#define MAX_PACKET_DATA ((size_t)1500)
#define MAX_PACKETS ((size_t)100)
#define BLOCKED_PORT 80U

/* Simplified packet structure */
typedef struct {
    size_t length;
    uint8_t *data;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} Packet;

/* Function 1: Memory allocation for packets
 * Annotated with because it can return NULL on failure.
 */

static /*@null@*/ Packet * allocate_packet_buffer(size_t num_packets)
{
    Packet *packets;
    size_t i, j, k;

    /* basic sanity limits */
    if (num_packets == 0 || num_packets > MAX_PACKETS) {
        return NULL;
    }

    packets = (Packet *) calloc(num_packets, sizeof(Packet));
    if (packets == NULL) {
        return NULL;
    }

    /* initialize entries so Splint knows fields are defined */
    for (k = 0; k < num_packets; k++) {
        packets[k].data = NULL;
        packets[k].length = 0;
        packets[k].src_port = 0;
        packets[k].dst_port = 0;
        packets[k].protocol = 0;
    }

    for (i = 0; i < num_packets; i++) {
        packets[i].data = (uint8_t *) malloc(MAX_PACKET_DATA);
        if (packets[i].data == NULL) {
            /* cleanup previously allocated buffers */
            for (j = 0; j < i; j++) {
                if (packets[j].data != NULL) {
                    free(packets[j].data);
                    packets[j].data = NULL;
                }
            }
            free(packets);
            return NULL;
        }
        packets[i].length = MAX_PACKET_DATA;
        packets[i].src_port = 0;
        packets[i].dst_port = 0;
        packets[i].protocol = 0;
    }

    return packets;
}

/* Function 2: Packet bounds checking
 * Accepts const Packet * (no modification); returns 0 on OK, -1 on error.
 */
static int validate_packet_bounds(const Packet *pkt)
{
    if (pkt == NULL) {
        return -1;
    }

    if (pkt->length > MAX_PACKET_DATA) {
        return -1;
    }

    if (pkt->length < sizeof(uint16_t)) {
        return -1;
    }
    return 0;
}

/* Function 3: Port initialization
 * All variable declarations at top to avoid Splint parse errors.
 */
static int initialize_ports(int *ports, size_t num_ports)
{
    size_t i;

    if (ports == NULL) {
        return -1;
    }
    if (num_ports == 0) {
        return -1;
    }

    /* loop strictly less than num_ports to avoid off-by-one */
    for (i = 0; i < num_ports; i++) {
        ports[i] = (int) i;
    }
    return 0;
}

/* Function 4: Packet inspection (core logic) */
static int inspect_packet(const Packet *pkt)
{
    int result = 0;

    if (pkt == NULL) {
        return -1;
    }

    /* validate packet first */
    if (validate_packet_bounds(pkt) != 0) {
        return -1;
    }

    /* If TCP and matches blocked port, block */
    if (pkt->protocol == 6) { /* TCP */
        if (pkt->dst_port == (uint16_t) BLOCKED_PORT) {
            return -1; /* Block packet */
        }
    }

    if (result > 0) {
        return 1;
    }

    return 0; /* Allow packet */
}

/* Test function */
int main(void)
{
    Packet *packets;
    int ports[5] = {0, 0, 0, 0, 0};
    Packet test_pkt;
    size_t i;

    /* allocate packets */
    packets = allocate_packet_buffer(10);
    if (packets == NULL) {
        fprintf(stderr, "Warning: packet buffer allocation failed; continuing with local test packet\n");
    }

    /* initialize ports array safely */
    if (initialize_ports(ports, sizeof(ports)/sizeof(ports[0])) != 0) {
        fprintf(stderr, "Failed to initialize ports\n");
    }

    /* Test packet inspection: initialize struct fully */
    memset(&test_pkt, 0, sizeof(test_pkt));
    test_pkt.length = sizeof(uint16_t);
    test_pkt.dst_port = (uint16_t) BLOCKED_PORT;
    test_pkt.protocol = 6;

    printf("Inspecting test packet...\n");
    printf("Packet decision: %d\n", inspect_packet(&test_pkt));

    /* cleanup */
    if (packets != NULL) {
        for (i = 0; i < 10; i++) {
            if (packets[i].data != NULL) {
                free(packets[i].data);
                packets[i].data = NULL;
            }
        }
        free(packets);
        packets = NULL;
    }

    /* ensure any local data pointer is released (safe no-op if NULL) */
    if (test_pkt.data != NULL) {
        free(test_pkt.data);
        test_pkt.data = NULL;
    }

    return 0;
}
