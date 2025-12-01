/*
 * Splint-friendly firewall demo
 *
 * Notes:
 *  - allocate_packet_buffer is annotated with @null@ to indicate it may return NULL.
 *  - All variables are declared at function starts (C89 style) to avoid Splint parse errors.
 *  - Defensive null checks and proper initialization added.
 *  - Use simple Splint annotations; remove -nullret if you prefer to annotate instead.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* constants */
#define MAX_PACKET_DATA 1500U
#define MAX_PACKETS 100U
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
 * Annotated with @null@ because it can return NULL on failure.
 */
 /*@null@*/ Packet * allocate_packet_buffer(size_t num_packets)
{
    Packet *packets;
    size_t i, j;

    /* basic sanity limits */
    if (num_packets == 0 || num_packets > MAX_PACKETS) {
        return NULL;
    }

    packets = (Packet *) malloc(num_packets * sizeof(Packet));
    if (packets == NULL) {
        return NULL;
    }

    for (i = 0; i < num_packets; i++) {
        packets[i].data = (uint8_t *) malloc(MAX_PACKET_DATA);
        if (packets[i].data == NULL) {
            /* cleanup previously allocated buffers */
            for (j = 0; j < i; j++) {
                free(packets[j].data);
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
int validate_packet_bounds(const Packet *pkt)
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
int initialize_ports(int *ports, size_t num_ports)
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
int inspect_packet(const Packet *pkt)
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
    int ports[5];
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
            free(packets[i].data);
        }
        free(packets);
    }

    return 0;
}