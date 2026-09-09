/*
 * See r2p2_glue.h for the role of this file: it implements the
 * "implementation specific" backend surface required by
 * r2p2/r2p2/inc/r2p2/api-internal.h so that r2p2/r2p2/r2p2-common.c (the
 * vendored, unmodified R2P2 protocol core) can run directly on top of the
 * mbufs that main.c's main_loop() already receives, instead of the
 * standalone r2p2 project's own network stack / poll loop.
 */
#include <string.h>
#include <sys/time.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

#include <r2p2/api-internal.h>

#include "hashmap.h"
#include "r2p2_glue.h"

#define MAX_LEARNED_MACS 4096

/* Set once from main() before the lcores are launched. */
static uint32_t g_local_ip_be;
static uint16_t g_local_port_be;
static struct rte_ether_addr g_local_mac;

/*
 * R2P2 addresses (struct r2p2_host_tuple) carry no MAC, unlike the
 * standalone r2p2 project which resolves one via a static ARP table
 * loaded from r2p2.conf. Instead, mirroring this codebase's existing
 * mac_updating()/MAGLEV convention of not doing real ARP resolution, we
 * just remember the source MAC of every request we see and reuse it for
 * the matching reply -- shared across lcores, same non-locked convention
 * already used by MAGLEV's active_sessions/services/backends hashmaps.
 */
static struct hashmap g_ip_to_mac;

/*
 * DPDK 20.11's struct rte_mbuf has no free-standing "userdata" pointer
 * field (older DPDK versions the standalone r2p2/netstack backend was
 * written against did), so the "next buffer in this reply's chain" link
 * is kept in a registered dynamic mbuf field instead -- the supported
 * way (rte_mbuf_dyn.h) to attach a private per-mbuf pointer without an
 * ABI-breaking struct change. Registered once in r2p2_glue_global_init().
 */
static int g_next_buf_offset = -1;

/* Set by r2p2_glue_on_request() for the packet currently being
 * processed; buf_list_send() reads it a few stack frames down, all
 * within the same lcore/call stack that received the request. */
static __thread uint16_t tls_tx_portid;
static __thread uint16_t tls_tx_queue;
static __thread struct rte_mempool *tls_tx_pool;

static void r2p2_glue_stss_init(void);

void r2p2_glue_global_init(uint32_t local_ip_be, uint16_t local_port_be,
							const struct rte_ether_addr *local_mac)
{
	static const struct rte_mbuf_dynfield next_buf_desc = {
		.name = "r2p2_glue_next_buf",
		.size = sizeof(generic_buffer),
		.align = __alignof__(generic_buffer),
		.flags = 0,
	};

	g_local_ip_be = local_ip_be;
	g_local_port_be = local_port_be;
	rte_ether_addr_copy(local_mac, &g_local_mac);

	if (!hashmap_init(&g_ip_to_mac, sizeof(uint32_t),
					  sizeof(struct rte_ether_addr), MAX_LEARNED_MACS))
		rte_exit(EXIT_FAILURE, "r2p2_glue: failed to allocate MAC learning table\n");

	g_next_buf_offset = rte_mbuf_dynfield_register(&next_buf_desc);
	if (g_next_buf_offset < 0)
		rte_exit(EXIT_FAILURE, "r2p2_glue: failed to register mbuf dynfield\n");

	r2p2_glue_stss_init(); // harmless (1 memset) even if application != R2P2_STSS
}

void r2p2_glue_prep_rx(struct rte_mbuf *m, uint16_t l2_len, uint16_t l3_len,
					   uint16_t l4_len)
{
	m->l2_len = l2_len;
	m->l3_len = l3_len;
	m->l4_len = l4_len;
	*RTE_MBUF_DYNFIELD(m, g_next_buf_offset, generic_buffer *) = NULL;
}

void r2p2_glue_init_per_core(void)
{
	r2p2_backend_init_per_core();
}

void r2p2_glue_on_request(uint16_t portid, uint16_t queue_id,
						  struct rte_mempool *pool, uint32_t src_ip_be,
						  const struct rte_ether_addr *src_mac)
{
	tls_tx_portid = portid;
	tls_tx_queue = queue_id;
	tls_tx_pool = pool;

	if (!hashmap_insert_elem(&g_ip_to_mac, &src_ip_be, (void *)src_mac))
		hashmap_update_elem(&g_ip_to_mac, &src_ip_be, (void *)src_mac);
}

/*
 * Generic buffer API: generic_buffer == struct rte_mbuf *.
 *
 * The r2p2 header/payload doesn't start at mtod(m) -- it starts after
 * whatever Eth/IPv4/UDP headers precede it. Rather than a parallel
 * struct (net_sge in the standalone project), that offset is kept in
 * the mbuf's own l2_len/l3_len/l4_len fields: process_r2p2() sets them
 * from the parsed headers for received mbufs, get_buffer() sets them to
 * the fixed reserve for freshly allocated reply mbufs.
 */
static inline uint16_t hdr_len(const struct rte_mbuf *m)
{
	return m->l2_len + m->l3_len + m->l4_len;
}

void free_buffer(generic_buffer buffer)
{
	rte_pktmbuf_free((struct rte_mbuf *)buffer);
}

generic_buffer get_buffer(void)
{
	struct rte_mbuf *m;

	/*
	 * This codebase builds with -DNDEBUG everywhere (see Makefile), which
	 * makes assert() a complete no-op -- it does not even evaluate its
	 * argument. Every call below that must actually run uses an explicit
	 * check instead, never a bare assert().
	 */
	if (!tls_tx_pool)
		rte_exit(EXIT_FAILURE, "r2p2_glue: get_buffer() called before r2p2_glue_on_request()\n");

	m = rte_pktmbuf_alloc(tls_tx_pool);
	if (!m)
		rte_exit(EXIT_FAILURE, "r2p2_glue: get_buffer: mbuf pool exhausted\n");

	r2p2_glue_prep_rx(m, RTE_ETHER_HDR_LEN, sizeof(struct rte_ipv4_hdr),
					 sizeof(struct rte_udp_hdr));

	if (!rte_pktmbuf_append(m, R2P2_GLUE_HDR_RESERVE))
		rte_exit(EXIT_FAILURE, "r2p2_glue: get_buffer: mbuf too small for header reserve\n");

	return (generic_buffer)m;
}

void *get_buffer_payload(generic_buffer gb)
{
	struct rte_mbuf *m = (struct rte_mbuf *)gb;
	return rte_pktmbuf_mtod_offset(m, void *, hdr_len(m));
}

uint32_t get_buffer_payload_size(generic_buffer gb)
{
	struct rte_mbuf *m = (struct rte_mbuf *)gb;
	return m->data_len - hdr_len(m);
}

int set_buffer_payload_size(generic_buffer gb, uint32_t payload_size)
{
	struct rte_mbuf *m = (struct rte_mbuf *)gb;
	uint32_t new_total = hdr_len(m) + payload_size;

	if (new_total > m->data_len) {
		if (!rte_pktmbuf_append(m, new_total - m->data_len))
			rte_exit(EXIT_FAILURE, "r2p2_glue: set_buffer_payload_size: mbuf too small\n");
	} else if (new_total < m->data_len) {
		if (rte_pktmbuf_trim(m, m->data_len - new_total) != 0)
			rte_exit(EXIT_FAILURE, "r2p2_glue: set_buffer_payload_size: trim failed\n");
	}

	return 0;
}

int chain_buffers(generic_buffer first, generic_buffer second)
{
	struct rte_mbuf *m = (struct rte_mbuf *)first;
	*RTE_MBUF_DYNFIELD(m, g_next_buf_offset, generic_buffer *) = second;
	return 0;
}

generic_buffer get_buffer_next(generic_buffer gb)
{
	struct rte_mbuf *m = (struct rte_mbuf *)gb;
	return *RTE_MBUF_DYNFIELD(m, g_next_buf_offset, generic_buffer *);
}

/*
 * Implementation-specific R2P2 backend functions.
 */
int buf_list_send(generic_buffer first_buf, struct r2p2_host_tuple *dest,
				  __attribute__((unused)) void *socket_info)
{
	generic_buffer gb, next;
	struct rte_mbuf *m;
	struct rte_ether_hdr *eth;
	struct rte_ipv4_hdr *ip;
	struct rte_udp_hdr *udp;
	struct rte_ether_addr *dst_mac;
	uint32_t r2p2_len;

	gb = first_buf;
	while (gb) {
		next = get_buffer_next(gb);
		m = (struct rte_mbuf *)gb;

		r2p2_len = get_buffer_payload_size(gb);

		eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		ip = (struct rte_ipv4_hdr *)(eth + 1);
		udp = (struct rte_udp_hdr *)(ip + 1);

		dst_mac = hashmap_lookup_elem(&g_ip_to_mac, &dest->ip);
		if (dst_mac)
			rte_ether_addr_copy(dst_mac, &eth->d_addr);
		else
			memset(&eth->d_addr, 0xFF, sizeof(eth->d_addr)); // unknown dest: broadcast
		rte_ether_addr_copy(&g_local_mac, &eth->s_addr);
		eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

		ip->version_ihl = 0x45;
		ip->type_of_service = 0;
		ip->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
											sizeof(struct rte_udp_hdr) + r2p2_len);
		ip->packet_id = 0;
		ip->fragment_offset = 0;
		ip->time_to_live = 64;
		ip->next_proto_id = IPPROTO_UDP;
		ip->hdr_checksum = 0; // see main.c: this codebase doesn't compute IP/UDP checksums anywhere
		ip->src_addr = g_local_ip_be;
		ip->dst_addr = dest->ip;

		udp->src_port = g_local_port_be;
		udp->dst_port = dest->port;
		udp->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + r2p2_len);
		udp->dgram_cksum = 0; // 0 is a valid "no checksum" for UDP/IPv4

		if (rte_eth_tx_burst(tls_tx_portid, tls_tx_queue, &m, 1) == 0)
			rte_pktmbuf_free(m);

		gb = next;
	}

	return 0;
}

int prepare_to_send(__attribute__((unused)) struct r2p2_client_pair *cp)
{
	// Client (outgoing request) path -- unused by this server-only glue.
	return -1;
}

int disarm_timer(__attribute__((unused)) void *timer)
{
	// Client (outgoing request) path -- unused by this server-only glue.
	return 0;
}

void router_notify(__attribute__((unused)) uint32_t ip,
					__attribute__((unused)) uint16_t port,
					__attribute__((unused)) uint16_t rid)
{
	// No FDIR/ACCELERATED in-network router support in this integration.
}

/*
 * Application logic: R2P2_ECHO -- echo the received payload back.
 */
void r2p2_glue_echo_recv(long handle, struct iovec *iov, int iovcnt)
{
	r2p2_send_response(handle, iov, iovcnt);
}

/*
 * Application logic: R2P2_STSS ("synthetic size+time server"), mirroring
 * r2p2/dpdk-apps/r2p2-stss.c's synthetic_recv_fn().
 */
#define STSS_MAX_REPLY (1024 * 1024) // matches r2p2-stss.c's MAX_REPLY

static char g_stss_payload[STSS_MAX_REPLY];

static void r2p2_glue_stss_init(void)
{
	memset(g_stss_payload, 'x', sizeof(g_stss_payload)); // r2p2-stss.c:97
}

static inline int64_t stss_time_us(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (int64_t)tv.tv_sec * 1000000 + (int64_t)tv.tv_usec;
}

static void stss_spin(int64_t usec)
{
	int64_t start = stss_time_us();
	while (stss_time_us() < start + usec)
		;
}

void r2p2_glue_stss_recv(long handle, struct iovec *iov, int iovcnt)
{
	const int64_t *hdr;
	int64_t spin_us, req_size, rep_size, received;
	struct iovec resp_iov[2];
	int i;

	/*
	 * r2p2-stss.c validates all of this with assert() -- a no-op under
	 * this project's -DNDEBUG build (see get_buffer() above). Here a
	 * malformed/out-of-range request is dropped explicitly instead,
	 * rather than risking an out-of-bounds read/write in production.
	 */
	if (iovcnt < 1 || iov[0].iov_len < 3 * sizeof(int64_t))
		return;

	hdr = (const int64_t *)iov[0].iov_base;
	spin_us = hdr[0];
	req_size = hdr[1];
	rep_size = hdr[2];

	received = 0;
	for (i = 0; i < iovcnt; i++)
		received += (int64_t)iov[i].iov_len;

	if (spin_us < 0 || req_size < 0 || rep_size < 0 ||
		received != (int64_t)(3 * sizeof(int64_t)) + req_size ||
		rep_size > STSS_MAX_REPLY)
		return;

	stss_spin(spin_us);

	resp_iov[0].iov_base = &rep_size;
	resp_iov[0].iov_len = sizeof(rep_size);
	resp_iov[1].iov_base = g_stss_payload;
	resp_iov[1].iov_len = rep_size;

	r2p2_send_response(handle, resp_iov, 2);
}
