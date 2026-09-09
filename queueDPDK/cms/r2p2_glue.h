/*
 * Glue layer that plugs the backend-agnostic R2P2 protocol core
 * (r2p2/r2p2/r2p2-common.c, vendored as-is from the r2p2/ EPFL project)
 * into queueDPDK/cms's single "dol" binary, the same way process_packet()
 * in main.c dispatches to CMS/MAGLEV/MICA.
 *
 * Unlike the standalone r2p2 project (netstack/ + dpdk-apps/), this glue
 * does NOT own the RX loop, port/queue setup or EAL init: main.c's
 * main_loop() already does rte_eth_rx_burst() and hands us one mbuf at a
 * time via process_r2p2(). This file only implements the small
 * "implementation specific" surface that r2p2/r2p2/inc/r2p2/api-internal.h
 * requires from a backend:
 *   - the generic_buffer API, backed directly by struct rte_mbuf*
 *     (no net_sge wrapper, no separate mempool -- header lengths are kept
 *     in the mbuf's own l2_len/l3_len/l4_len fields)
 *   - buf_list_send() -- builds Eth/IPv4/UDP headers and transmits with
 *     rte_eth_tx_burst()
 *   - prepare_to_send()/disarm_timer()/router_notify() -- stubs, never
 *     exercised by a server-only integration: rte_timer and the
 *     client-pair path are only used when *sending* R2P2 requests, which
 *     neither app below ever does (confirmed by reading r2p2-common.c).
 *
 * Two applications share this same backend, differing only in which
 * recv_fn is registered with r2p2_set_recv_cb() in main() (main.c:
 * application R2P2_ECHO vs R2P2_STSS):
 *   - r2p2_glue_echo_recv()  -- mirrors r2p2/dpdk-apps/r2p2-echo.c
 *   - r2p2_glue_stss_recv()  -- mirrors r2p2/dpdk-apps/r2p2-stss.c
 *     ("synthetic size+time server": client picks how long the server
 *     spins and how big the reply is)
 *
 * Server-only: this glue only knows how to receive R2P2 requests and
 * send R2P2 responses (r2p2_send_req()/client pairs are unsupported).
 */
#pragma once

#include <stdint.h>
#include <sys/uio.h>

#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <r2p2/api-internal.h> // generic_buffer, handle_incoming_pck() -- needed by main.c's process_r2p2()
#include <r2p2/api.h>

/* Ethernet(14) + IPv4 without options(20) + UDP(8): the header room
 * reserved in every freshly allocated reply buffer (get_buffer()). */
#define R2P2_GLUE_HDR_RESERVE 42

/*
 * Called once from main() (not per-lcore) before the lcores are
 * launched, when application is R2P2_ECHO or R2P2_STSS. ip/port are
 * already in network byte order (e.g. straight out of
 * inet_addr()/htons()), matching the byte order process_r2p2() uses for
 * the source tuples it passes to handle_incoming_pck() -- see main.c's
 * process_r2p2().
 */
void r2p2_glue_global_init(uint32_t local_ip_be, uint16_t local_port_be,
							const struct rte_ether_addr *local_mac);

/*
 * Called once per lcore (from main_loop(), before the RX loop) when
 * application is R2P2_ECHO or R2P2_STSS. Allocates the per-lcore r2p2
 * server-pair pools (r2p2_backend_init_per_core()).
 */
void r2p2_glue_init_per_core(void);

/*
 * Called by process_r2p2() for every received R2P2 packet, before
 * handle_incoming_pck(): records where a reply for this request should
 * be sent out (port/queue/pool) and learns src_ip -> src_mac so
 * buf_list_send() can address the reply without a real ARP table.
 */
void r2p2_glue_on_request(uint16_t portid, uint16_t queue_id,
						  struct rte_mempool *pool, uint32_t src_ip_be,
						  const struct rte_ether_addr *src_mac);

/*
 * Called by process_r2p2() on a just-received mbuf, before
 * handle_incoming_pck(): records the Eth/IPv4/UDP header lengths this
 * mbuf was parsed with (so get_buffer_payload() et al. can find the r2p2
 * payload) and clears this glue's private "next reply buffer" chain
 * link (r2p2 mbufs can arrive out of a pool that reused them from a
 * previous chain).
 */
void r2p2_glue_prep_rx(struct rte_mbuf *m, uint16_t l2_len, uint16_t l3_len,
					   uint16_t l4_len);

/* recv_fn for application R2P2_ECHO: echoes the payload back. */
void r2p2_glue_echo_recv(long handle, struct iovec *iov, int iovcnt);

/*
 * recv_fn for application R2P2_STSS ("synthetic size+time server"),
 * mirroring r2p2/dpdk-apps/r2p2-stss.c's synthetic_recv_fn(): the
 * request payload is 3 packed int64_t's -- spin_us, req_size, rep_size
 * -- followed by req_size padding bytes. The handler busy-spins for
 * spin_us microseconds, then replies with rep_size bytes of fixed
 * ('x') payload (as [int64_t rep_size][rep_size bytes], 2 iovecs,
 * exactly like upstream).
 */
void r2p2_glue_stss_recv(long handle, struct iovec *iov, int iovcnt);
