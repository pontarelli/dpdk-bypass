/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include "rte_pmd_qdma.h"
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <locale.h>
#include <netinet/in.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_prefetch.h>
#include <rte_random.h>
#include <rte_string_fns.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>

struct rte_eth_stats stats;
uint16_t             port_id = 0;
#define HASHFN_N 40
#define COLUMNS 1048576
// #define COLUMNS 1024
struct countmin {
	uint64_t **values;
};

struct countmin *cm;

static volatile bool force_quit;

/* MAC updating enabled by default */
static int mac_updating = 1;

#define RTE_LOGTYPE_CMS RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct rte_ether_addr cms_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t cms_enabled_port_mask = 0;

/* list of enabled ports */
static uint32_t cms_dst_ports[RTE_MAX_ETHPORTS];

struct port_pair_params {
#define NUM_PORTS 2
#define NUM_PORTS 2
	uint16_t port[NUM_PORTS];
} __rte_cache_aligned;

static struct port_pair_params  port_pair_params_array[RTE_MAX_ETHPORTS / 2];
static struct port_pair_params  port_pair_params_array[RTE_MAX_ETHPORTS / 2];
static struct port_pair_params *port_pair_params;
static uint16_t                 nb_port_pair_params;
static uint16_t                 nb_port_pair_params;

static unsigned int cms_rx_queue_per_lcore = 2;

#define MAX_RX_QUEUE_PER_LCORE 2048
#define MAX_TX_QUEUE_PER_PORT 2048
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
    .rxmode =
        {
            .mq_mode = ETH_MQ_RX_RSS,
        },
    .rx_adv_conf =
        {
            .rss_conf =
                {
                    .rss_key = NULL,
                    .rss_hf  = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP,
                },
        },
    .txmode =
        {
            .mq_mode = ETH_MQ_TX_NONE,
        },
};

struct rte_mempool *cms_pktmbuf_pool = NULL;
/* Per-port statistics struct */
struct cms_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct cms_port_statistics port_statistics[RTE_MAX_ETHPORTS][MAX_RX_QUEUE_PER_LCORE];

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period      = 10; /* default period is 10 seconds */
uint32_t        spin_time         = 0;
uint32_t        miss              = 0;
uint32_t        total             = 0;
uint32_t        skipped           = 0;
bool            aggressive        = false;   /* aggressive mode disabled by default */
static unsigned prefetch_distance = 4;       /* prefetch distance for mbufs in burst */
uint32_t        cms_columns       = COLUMNS; /* number of columns in the count-min sketch */
bool            after_warmup      = false;   /* reset statistics after warmup time */
/* Print out statistics on packets dropped */
uint64_t measured_packets_rx = 0;
uint64_t measured_tick       = 0;
uint64_t locality_factor     = 0; // lunghezza corrente del blocco
uint64_t total_locality      = 0; // somma di tutte le lunghezze dei blocchi
uint64_t flow_blocks         = 0; // numero di blocchi
uint64_t max_locality_factor = 0; // massimo trovato

static void
print_stats(void)
{
	uint64_t        total_packets_dropped = 0, total_packets_tx = 0, total_packets_rx = 0;
	static uint64_t total_packets_tx_prev = 0, total_packets_rx_prev = 0,
	                total_packets_dropped_prev = 0;

	unsigned portid;

	/* Static variables to store previous statistics */
	static uint64_t prev_tx[RTE_MAX_ETHPORTS][MAX_RX_QUEUE_PER_LCORE]      = {0};
	static uint64_t prev_rx[RTE_MAX_ETHPORTS][MAX_RX_QUEUE_PER_LCORE]      = {0};
	static uint64_t prev_dropped[RTE_MAX_ETHPORTS][MAX_RX_QUEUE_PER_LCORE] = {0};

	const char clr[]     = {27, '[', '2', 'J', '\0'};
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

	/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((cms_enabled_port_mask & (1 << portid)) == 0)
			continue;

		for (int q = 0; q < cms_rx_queue_per_lcore; q++) {

			uint64_t diff_tx      = port_statistics[portid][q].tx - prev_tx[portid][q];
			uint64_t diff_rx      = port_statistics[portid][q].rx - prev_rx[portid][q];
			uint64_t diff_dropped = port_statistics[portid][q].dropped - prev_dropped[portid][q];

			if (diff_tx == 0 && diff_rx == 0 && diff_dropped == 0)
				continue;
			printf("\nStatistics for port %u queue: %d ------------------------------"
			       "\nPackets sent:     %'20llu (diff: %'llu)"
			       "\nPackets received: %'20llu (diff: %'llu)"
			       "\nPackets dropped:  %'20llu (diff: %'llu)\n",
			       portid,
			       q,
			       (unsigned long long)port_statistics[portid][q].tx,
			       (unsigned long long)diff_tx,
			       (unsigned long long)port_statistics[portid][q].rx,
			       (unsigned long long)diff_rx,
			       (unsigned long long)port_statistics[portid][q].dropped,
			       (unsigned long long)diff_dropped);

			total_packets_dropped += port_statistics[portid][q].dropped;
			total_packets_tx += port_statistics[portid][q].tx;
			total_packets_rx += port_statistics[portid][q].rx;
			/* Update previous statistics */
			prev_tx[portid][q]      = port_statistics[portid][q].tx;
			prev_rx[portid][q]      = port_statistics[portid][q].rx;
			prev_dropped[portid][q] = port_statistics[portid][q].dropped;
		}
	}
	printf("\nAggregate statistics ==============================="
	       "\nTotal Packets sent:     %'14llu (diff: %'llu)"
	       "\nTotal Packets received: %'14llu (diff: %'llu)"
	       "\nTotal Packets dropped:  %'14llu (diff: %'llu)\n",
	       (unsigned long long)total_packets_tx,
	       (unsigned long long)(total_packets_tx - total_packets_tx_prev),
	       (unsigned long long)total_packets_rx,
	       (unsigned long long)(total_packets_rx - total_packets_rx_prev),
	       (unsigned long long)total_packets_dropped,
	       (unsigned long long)(total_packets_dropped - total_packets_dropped_prev));
	printf("\nspin time: %u\n", spin_time);
	printf("\n max locality factor: %lu\n", max_locality_factor);
	if (aggressive)
		printf("With aggressive policy\n");
	else
		printf("Without aggressive policy\n");
	printf("prefetch distance: %u\n", prefetch_distance);
	printf("\n====================================================\n");
	if (after_warmup)
		measured_packets_rx += (total_packets_rx - total_packets_rx_prev);
	if (after_warmup)
		measured_tick++;
	/* Reset previous statistics */
	total_packets_tx_prev      = total_packets_tx;
	total_packets_rx_prev      = total_packets_rx;
	total_packets_dropped_prev = total_packets_dropped;

	if (rte_eth_stats_get(port_id, &stats) < 0) {
		printf("Error getting stats for port %u\n", port_id);
	}

	fflush(stdout);
}

static void
cms_mac_updating(struct rte_mbuf *m, unsigned dest_portid)
{
	struct rte_ether_hdr *eth;
	void                 *tmp;

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	/* 02:00:00:00:00:xx */
	tmp                = &eth->d_addr.addr_bytes[0];
	tmp                = &eth->d_addr.addr_bytes[0];
	*((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dest_portid << 40);

	/* src addr */
	rte_ether_addr_copy(&cms_ports_eth_addr[dest_portid], &eth->s_addr);
}

static void
cms_simple_forward(struct rte_mbuf *m, unsigned portid)
{
	unsigned                      dst_port;
	int                           sent;
	struct rte_eth_dev_tx_buffer *buffer;

	dst_port = cms_dst_ports[portid];

	if (mac_updating)
		cms_mac_updating(m, dst_port);

	buffer = tx_buffer[dst_port];
	sent   = rte_eth_tx_buffer(dst_port, 0, buffer, m);
	if (sent)
		port_statistics[dst_port][0].tx += sent;
}

static double   global_total_locality = 0.0;
static uint64_t global_flow_blocks    = 0;
static uint64_t global_packets        = 0;
static uint64_t global_max_locality   = 0;
double          global_avg_sum        = 0.0;
uint64_t        total_bursts          = 0;

/* main processing loop */
static void
cms_main_loop(uint16_t *penality_list)
{
	struct rte_mbuf         *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf         *m;
	int                      sent;
	unsigned                 lcore_id;
	uint64_t                 prev_tsc, diff_tsc, cur_tsc, timer_tsc, end_time;
	unsigned                 i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
	struct rte_eth_dev_tx_buffer *buffer;

	prev_tsc  = 0;
	timer_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf    = &lcore_queue_conf[lcore_id];

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, CMS, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, CMS, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, CMS, " -- lcoreid=%u portid=%u\n", lcore_id, portid);
		RTE_LOG(INFO, CMS, " -- lcoreid=%u portid=%u\n", lcore_id, portid);
	}

	uint64_t start_time  = rte_rdtsc();
	uint64_t warmup_time = 3 * rte_get_timer_hz();
	uint64_t stop_time   = (10 * rte_get_timer_hz()) + warmup_time;
	while (!force_quit) {

		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (i = 0; i < qconf->n_rx_port; i++) {

				portid = cms_dst_ports[qconf->rx_port_list[i]];
				buffer = tx_buffer[portid];
				sent   = rte_eth_tx_buffer_flush(portid, 0, buffer);
				if (sent)
					port_statistics[portid][0].tx += sent;
			}

			/* if timer is enabled */
			if (timer_period > 0) {

				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= timer_period)) {

					/* do this only on main core */
					if (lcore_id == rte_get_main_lcore()) {
						// print_stats();
						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;
		}
		/*
		 * Read packet from RX queues
		 */
		int max_loops = 100000;
		for (i = 0; i < qconf->n_rx_port; i++) {
			portid = qconf->rx_port_list[i];
			// for (int q = 1923; q < 1924; q++) {
			for (int q = 0; q < cms_rx_queue_per_lcore; q++) {
				nb_rx = rte_eth_rx_burst(portid, q, pkts_burst, MAX_PKT_BURST);

				uint64_t locality_factor     = 0;
				uint64_t total_locality      = 0;
				uint64_t flow_blocks         = 0;
				uint64_t max_locality_factor = 0;

				uint32_t prev_src_ip = 0, prev_dst_ip = 0;
				uint16_t prev_src_port = 0, prev_dst_port = 0;
				uint8_t  prev_proto   = 0;
				bool     first_packet = true;

				port_statistics[portid][q].rx += nb_rx;

				for (j = 0; j < nb_rx; j++) {
					m = pkts_burst[j];
					if (j + prefetch_distance < nb_rx)
						rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j + prefetch_distance], void *));

					struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

					if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
						rte_pktmbuf_free(m);
						continue;
					}

					struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth + 1);
					uint32_t             src_ip   = rte_be_to_cpu_32(ipv4_hdr->src_addr);
					uint32_t             dst_ip   = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
					uint8_t              proto    = ipv4_hdr->next_proto_id;
					uint16_t             src_port = 0, dst_port = 0;

					if (proto == IPPROTO_TCP) {
						struct rte_tcp_hdr *tcp_hdr =
						    (struct rte_tcp_hdr *)((unsigned char *)ipv4_hdr +
						                           sizeof(struct rte_ipv4_hdr));
						src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
						dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
					} else if (proto == IPPROTO_UDP) {
						struct rte_udp_hdr *udp_hdr =
						    (struct rte_udp_hdr *)((unsigned char *)ipv4_hdr +
						                           sizeof(struct rte_ipv4_hdr));
						src_port = rte_be_to_cpu_16(udp_hdr->src_port);
						dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
					} else {
						rte_pktmbuf_free(m);
						continue;
					}

					// if (first_packet) {
					// 	// primo pacchetto del burst → inizializza
					// 	prev_src_ip     = src_ip;
					// 	prev_dst_ip     = dst_ip;
					// 	prev_src_port   = src_port;
					// 	prev_dst_port   = dst_port;
					// 	prev_proto      = proto;
					// 	locality_factor = 1;
					// 	first_packet    = false;
					// } else if (src_ip == prev_src_ip && dst_ip == prev_dst_ip &&
					//            src_port == prev_src_port && dst_port == prev_dst_port &&
					//            proto == prev_proto) {
					// 	locality_factor++;
					// 	if (locality_factor > max_locality_factor)
					// 		max_locality_factor = locality_factor;
					// } else {
					// 	total_locality += locality_factor;
					// 	flow_blocks++;
					// 	locality_factor = 1;

					// 	prev_src_ip   = src_ip;
					// 	prev_dst_ip   = dst_ip;
					// 	prev_src_port = src_port;
					// 	prev_dst_port = dst_port;
					// 	prev_proto    = proto;
					// }
					printf("%d,%u,%u,%u,%u,%u\n",
					   q, src_ip, dst_ip, src_port, dst_port, proto);
					rte_pktmbuf_free(m);
				}
				// chiudi l’ultimo blocco del burst
				if (!first_packet) {
					total_locality += locality_factor;
					flow_blocks++;
				}

				// --- Calcolo locality per burst ---
				double avg_locality_burst = 0.0;
				if (flow_blocks > 0)
					avg_locality_burst = (double)total_locality / flow_blocks;

				// --- Aggiorna statistiche globali ---
				global_total_locality += total_locality;
				global_flow_blocks += flow_blocks;
				global_packets += nb_rx;
				global_avg_sum += avg_locality_burst;
				total_bursts++;
				if (max_locality_factor > global_max_locality)
					global_max_locality = max_locality_factor;

				// --- Stampa ---
				// printf("Queue %d - Burst locality: avg = %.2f, max = %lu, packets = %d\n",
				//        q,
				//        avg_locality_burst,
				//        max_locality_factor,
				//        nb_rx);
				
			}
		}
		if ((cur_tsc - start_time) > stop_time) { // 13 seconds) {
			break;
		} else if (cur_tsc - start_time > warmup_time) { // 3 seconds
			// rte_eth_stats_reset(portid); // skip the first 3 seconds
			after_warmup = true;
			warmup_time  = 1000 * rte_get_timer_hz(); // reset warmup time
		}
	}
}

static int
cms_launch_one_lcore(void *arg)
{
	uint16_t *penality_list = (uint16_t *)arg;
	// for (int p = 0; p < cms_rx_queue_per_lcore; p++) {
	// 	printf(" %4u ", penality_list[p]);
	// }
	printf("\n");
	cms_main_loop(penality_list);
	return 0;
}

/* display usage */
static void
cms_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -d N: number of descriptors > 32 (default is 1024)\n"
	       "  -p N: prefetch distance\n"
	       "  -c N: configure number of columns (default is 1048576)\n"
	       "  -a enable aggressive policy\n"
	       "  -P PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
	       "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to "
	       "disable, 10 default, 86400 maximum)\n"
	       "  --[no-]mac-updating: Enable or disable MAC addresses updating "
	       "(enabled by default)\n"
	       "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to "
	       "disable, 10 default, 86400 maximum)\n"
	       "  --[no-]mac-updating: Enable or disable MAC addresses updating "
	       "(enabled by default)\n"
	       "      When enabled:\n"
	       "       - The source MAC address is replaced by the TX port MAC "
	       "address\n"
	       "       - The destination MAC address is replaced by "
	       "02:00:00:00:00:TX_PORT_ID\n"
	       "  --portmap: Configure forwarding port pair mapping\n"
	       "	      Default: alternate port pairs\n\n",
	       prgname);
}

static int
cms_parse_portmask(const char *portmask)
{
	char         *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return pm;
}

static int
cms_parse_port_pair_config(const char *q_arg)
{
	enum fieldnames { FLD_PORT1 = 0, FLD_PORT2, _NUM_FLD };
	unsigned long int_fld[_NUM_FLD];
	const char   *p, *p0 = q_arg;
	char         *str_fld[_NUM_FLD];
	unsigned int  size;
	char          s[256];
	char         *end;
	int           i;

	nb_port_pair_params = 0;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		memcpy(s, p, size);
		s[size] = '\0';
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno      = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] || int_fld[i] >= RTE_MAX_ETHPORTS)
				return -1;
		}
		if (nb_port_pair_params >= RTE_MAX_ETHPORTS / 2) {
			printf("exceeded max number of port pair params: %hu\n", nb_port_pair_params);
			return -1;
		}
		port_pair_params_array[nb_port_pair_params].port[0] = (uint16_t)int_fld[FLD_PORT1];
		port_pair_params_array[nb_port_pair_params].port[1] = (uint16_t)int_fld[FLD_PORT2];
		++nb_port_pair_params;
	}
	port_pair_params = port_pair_params_array;
	return 0;
}

static unsigned int
cms_parse_nqueue(const char *q_arg)
{
	char         *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	// if (n >= MAX_RX_QUEUE_PER_LCORE)
	// 	return 0;

	return n;
}

static int
cms_parse_timer_period(const char *q_arg)
{
	char *end = NULL;
	int   n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n >= MAX_TIMER_PERIOD)
		return -1;

	return n;
}

static const char short_options[] = "c:" /* columns  */
                                    "a"  /* agressive */
                                    "P:" /* portmask  */
                                    "q:" /* number of queues */
                                    "T:" /* timer period */
                                    "p:" /* prefetch distance */
                                    "d:" /* number of descriptors */
    ;

#define CMD_LINE_OPT_MAC_UPDATING "mac-updating"
#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"
#define CMD_LINE_OPT_PORTMAP_CONFIG "portmap"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_PORTMAP_NUM,
};

static const struct option lgopts[] = {
    {CMD_LINE_OPT_MAC_UPDATING, no_argument, &mac_updating, 1},
    {CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, &mac_updating, 0},
    {CMD_LINE_OPT_PORTMAP_CONFIG, 1, 0, CMD_LINE_OPT_PORTMAP_NUM},
    {NULL, 0, 0, 0}};

/* Parse the argument given in the command line of the application */
static int
cms_parse_args(int argc, char **argv)
{
	int    opt, ret, timer_secs;
	char **argvopt;
	int    option_index;
	char  *prgname = argv[0];

	argvopt          = argv;
	argvopt          = argv;
	port_pair_params = NULL;

	while ((opt = getopt_long(argc, argvopt, short_options, lgopts, &option_index)) != EOF) {
		switch (opt) {
		case 'c':
			cms_columns = cms_parse_nqueue(optarg);
			/* check that cms_columns is a power of 2 */
			if (cms_columns == 0 || (cms_columns & (cms_columns - 1)) != 0) {
				printf("invalid number of columns\n");
				cms_usage(prgname);
				return -1;
			}
			break;

		case 'd':
			nb_rxd = cms_parse_nqueue(optarg);
			/* check that descriptors is a power of 2 */
			if (nb_rxd < 32 || (nb_rxd & (nb_rxd - 1)) != 0) {
				printf("invalid number of descriptors\n");
				cms_usage(prgname);
				return -1;
			}
			break;
		case 'a':
			aggressive = true;
			break;
		case 'p':
			prefetch_distance = atoi(optarg);
			break;
		/* portmask */
		case 'P':
			cms_enabled_port_mask = cms_parse_portmask(optarg);
			if (cms_enabled_port_mask == 0) {
				printf("invalid portmask\n");
				cms_usage(prgname);
				return -1;
			}
			break;

		/* nqueue */
		case 'q':
			cms_rx_queue_per_lcore = cms_parse_nqueue(optarg);
			if (cms_rx_queue_per_lcore == 0) {
				printf("invalid queue number\n");
				cms_usage(prgname);
				return -1;
			}
			break;

		/* timer period */
		case 'T':
			timer_secs = cms_parse_timer_period(optarg);
			if (timer_secs < 0) {
				printf("invalid timer period\n");
				cms_usage(prgname);
				return -1;
			}
			timer_period = timer_secs;
			break;

		/* long options */
		case CMD_LINE_OPT_PORTMAP_NUM:
			ret = cms_parse_port_pair_config(optarg);
			if (ret) {
				fprintf(stderr, "Invalid config\n");
				cms_usage(prgname);
				return -1;
			}
			break;

		default:
			cms_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;
	ret    = optind - 1;
	ret    = optind - 1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/*
 * Check port pair config with enabled port mask,
 * and for valid port pair combinations.
 */
static int
check_port_pair_config(void)
{
	uint32_t port_pair_config_mask = 0;
	uint32_t port_pair_mask        = 0;
	uint16_t index, i, portid;

	for (index = 0; index < nb_port_pair_params; index++) {
		port_pair_mask = 0;

		for (i = 0; i < NUM_PORTS; i++) {
			portid = port_pair_params[index].port[i];
			if ((cms_enabled_port_mask & (1 << portid)) == 0) {
				printf("port %u is not enabled in port mask\n", portid);
				printf("port %u is not enabled in port mask\n", portid);
				return -1;
			}
			if (!rte_eth_dev_is_valid_port(portid)) {
				printf("port %u is not present on the board\n", portid);
				printf("port %u is not present on the board\n", portid);
				return -1;
			}

			port_pair_mask |= 1 << portid;
		}

		if (port_pair_config_mask & port_pair_mask) {
			printf("port %u is used in other port pairs\n", portid);
			return -1;
		}
		port_pair_config_mask |= port_pair_mask;
	}

	cms_enabled_port_mask &= port_pair_config_mask;

	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
	uint16_t            portid;
	uint8_t             count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int                 ret;
	char                link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid)
		{
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n", portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status_text, sizeof(link_status_text), &link);
				printf("Port %d %s\n", portid, link_status_text);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

int
main(int argc, char **argv)
{
	struct lcore_queue_conf *qconf;
	int                      ret;
	uint16_t                 nb_ports;
	uint16_t                 nb_ports_available = 0;
	uint16_t                 portid, last_port;
	unsigned                 lcore_id, rx_lcore_id;
	unsigned                 nb_ports_in_mask = 0;
	unsigned int             nb_lcores        = 0;
	unsigned int             nb_mbufs;

	setlocale(LC_NUMERIC, ""); // Usa locale di sistema per i separatori

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = cms_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid cms arguments\n");

	printf("MAC updating %s\n", mac_updating ? "enabled" : "disabled");

	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	if (port_pair_params != NULL) {
		if (check_port_pair_config() < 0)
			rte_exit(EXIT_FAILURE, "Invalid port pair config\n");
	}

	/* check port mask to possible port mask */
	if (cms_enabled_port_mask & ~((1 << nb_ports) - 1))
		rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n", (1 << nb_ports) - 1);

	/* reset cms_dst_ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		cms_dst_ports[portid] = 0;
	last_port = 0;

	/* populate destination port details */
	if (port_pair_params != NULL) {
		uint16_t idx, p;

		for (idx = 0; idx < (nb_port_pair_params << 1); idx++) {
			p                     = idx & 1;
			portid                = port_pair_params[idx >> 1].port[p];
			cms_dst_ports[portid] = port_pair_params[idx >> 1].port[p ^ 1];
		}
	} else {
		RTE_ETH_FOREACH_DEV(portid)
		{
			/* skip ports that are not enabled */
			if ((cms_enabled_port_mask & (1 << portid)) == 0)
				continue;

			if (nb_ports_in_mask % 2) {
				cms_dst_ports[portid]    = last_port;
				cms_dst_ports[last_port] = portid;
			} else {
				last_port = portid;
			}

			nb_ports_in_mask++;
		}
		if (nb_ports_in_mask % 2) {
			printf("Notice: odd number of ports in portmask.\n");
			cms_dst_ports[last_port] = last_port;
		}
	}

	rx_lcore_id = 0;
	qconf       = NULL;

	/* Initialize the port/queue configuration of each logical core */
	RTE_ETH_FOREACH_DEV(portid)
	{
		/* skip ports that are not enabled */
		if ((cms_enabled_port_mask & (1 << portid)) == 0)
			continue;

		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
		       lcore_queue_conf[rx_lcore_id].n_rx_port == cms_rx_queue_per_lcore) {
			rx_lcore_id++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}

		if (qconf != &lcore_queue_conf[rx_lcore_id]) {
			/* Assigned a new logical core in the loop above. */
			qconf = &lcore_queue_conf[rx_lcore_id];
			nb_lcores++;
		}

		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;
		printf("Lcore %u: RX port %u TX port %u\n", rx_lcore_id, portid, cms_dst_ports[portid]);
	}

	nb_mbufs = RTE_MAX(cms_rx_queue_per_lcore * nb_ports *
	                       (nb_rxd + nb_txd + MAX_PKT_BURST + nb_lcores * MEMPOOL_CACHE_SIZE),
	                   8192U);
	printf("Creating mbuf pool with %u mbufs\n", nb_mbufs);

	/* create the mbuf pool */
	cms_pktmbuf_pool = rte_pktmbuf_pool_create(
	    "mbuf_pool", nb_mbufs, MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (cms_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid)
	{
		struct rte_eth_rxconf   rxq_conf;
		struct rte_eth_txconf   txq_conf;
		struct rte_eth_conf     local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		/* skip ports that are not enabled */
		if ((cms_enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %u\n", portid);
			continue;
		}
		nb_ports_available++;

		/* init port */
		printf("Initializing port %u... ", portid);
		fflush(stdout);

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
			         "Error during getting device (port %u) info: %s\n",
			         portid,
			         strerror(-ret));

		// local_port_conf.rxmode.mq_mode              = ETH_MQ_RX_RSS;
		// local_port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP |
		// ETH_RSS_TCP | ETH_RSS_UDP;

		// modificare per mettere più code
		ret = rte_eth_dev_configure(portid, cms_rx_queue_per_lcore, 1, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", ret, portid);

		struct rte_eth_rss_reta_entry64 reta_conf[2048 / RTE_RETA_GROUP_SIZE];
		int                             i, j;
		// crea l'indir table con valori da 0 a cms_rx_queue_per_lcore
		for (i = 0; i < dev_info.reta_size / RTE_RETA_GROUP_SIZE; i++) {
			// select all fields to set //
			reta_conf[i].mask = ~0LL;
			for (j = 0; j < RTE_RETA_GROUP_SIZE; j++)
				// da 0 a number of queues
				reta_conf[i].reta[j] = 0;
		}
		// salva l'indir table sul device
		ret = rte_eth_dev_rss_reta_update(portid, reta_conf, dev_info.reta_size);
		if (ret < 0)
			// stampa errore
			rte_exit(EXIT_FAILURE, "Cannot set RSS REA: err=%d, port=%u\n", ret, portid);

		rte_eth_dev_rss_reta_query(portid, reta_conf, dev_info.reta_size);
		cms_rx_queue_per_lcore = reta_conf[0].reta[0] + 1;
		printf("cms_rx_queue_per_lcore: %d\n", cms_rx_queue_per_lcore);

		rte_eth_dev_info_get(portid, &dev_info);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			         "Cannot adjust number of descriptors: err=%d, "
			         "port=%u\n",
			         ret,
			         portid);

		ret = rte_eth_macaddr_get(portid, &cms_ports_eth_addr[portid]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot get MAC address: err=%d, port=%u\n", ret, portid);

		int      diag, x;
		uint32_t queue_base;
		diag = rte_pmd_qdma_get_queue_base(portid, &queue_base);
		if (diag < 0)
			rte_exit(EXIT_FAILURE,
			         "rte_pmd_qdma_get_queue_base : Querying of "
			         "QUEUE_BASE failed\n");
		// for loop sulle varie code
		/* init one RX queue */
		fflush(stdout);
		rxq_conf          = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;

		for (x = 0; x < cms_rx_queue_per_lcore; x++) {
			diag = rte_pmd_qdma_set_queue_mode(portid, x, RTE_PMD_QDMA_STREAMING_MODE);
			if (diag < 0)
				rte_exit(EXIT_FAILURE,
				         "rte_pmd_qdma_set_queue_mode : "
				         "Passing of STREAMING_MODE "
				         "failed\n");

			ret = rte_eth_rx_queue_setup(
			    portid, x, nb_rxd, rte_eth_dev_socket_id(portid), &rxq_conf, cms_pktmbuf_pool);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n", ret, portid);

			/* init one TX queue on each port */
			fflush(stdout);
			txq_conf          = dev_info.default_txconf;
			txq_conf.offloads = local_port_conf.txmode.offloads;
			ret =
			    rte_eth_tx_queue_setup(portid, 0, nb_txd, rte_eth_dev_socket_id(portid), &txq_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n", ret, portid);

			/* Initialize TX buffers */
			tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
			                                       RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST),
			                                       0,
			                                       rte_eth_dev_socket_id(portid));
			if (tx_buffer[portid] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n", portid);

			rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

			ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
			                                         rte_eth_tx_buffer_count_callback,
			                                         &port_statistics[portid][0].dropped);
			if (ret < 0)
				rte_exit(
				    EXIT_FAILURE, "Cannot set error callback for tx buffer on port %u\n", portid);

			ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL, 0);
			if (ret < 0)
				printf("Port %u, Failed to disable Ptype parsing\n", portid);

			// end queue loop
		}
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", ret, portid);

		printf("done: \n");

		// ret = rte_eth_promiscuous_enable(portid);
		// if (ret != 0)
		// 	rte_exit(EXIT_FAILURE,
		// 		 "rte_eth_promiscuous_enable:err=%s, port=%u\n",
		// 		 rte_strerror(-ret), portid);

		printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
		       portid,
		       cms_ports_eth_addr[portid].addr_bytes[0],
		       cms_ports_eth_addr[portid].addr_bytes[1],
		       cms_ports_eth_addr[portid].addr_bytes[2],
		       cms_ports_eth_addr[portid].addr_bytes[3],
		       cms_ports_eth_addr[portid].addr_bytes[4],
		       cms_ports_eth_addr[portid].addr_bytes[5]);

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));
	}

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE, "All available ports are disabled. Please set portmask.\n");
	}

	// start

	cm         = rte_zmalloc(NULL, sizeof(struct countmin), 64);
	cm->values = rte_zmalloc(NULL, sizeof(uint64_t *) * HASHFN_N, 64);
	for (int i = 0; i < HASHFN_N; i++) {
		cm->values[i] = rte_zmalloc(NULL, sizeof(uint64_t) * cms_columns, 64);
	}

	for (int i = 0; i < HASHFN_N; i++) {
		for (int j = 0; j < cms_columns; j++) {
			cm->values[i][j] = 0;
		}
	}

	check_all_ports_link_status(cms_enabled_port_mask);

	ret = 0;
	uint16_t penality_list[cms_rx_queue_per_lcore];
	memset(penality_list, 0, sizeof(penality_list));
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(cms_launch_one_lcore, penality_list, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}
	printf("RX packets: %" PRIu64 "\n", stats.ipackets);
	printf("TX packets: %" PRIu64 "\n", stats.opackets);
	printf("RX dropped: %" PRIu64 "\n", stats.imissed);
	// printf("measured RX: %" PRIu64 "\n", measured_packets_rx);
	printf("measured RX packets: %.2f\n", (float)measured_packets_rx);
	printf("measured RX Throughput: %.2f\n", (float)measured_packets_rx / measured_tick);

	// --- Calcola media totale ---
	double avg_locality_total = 0.0;
	if (global_flow_blocks > 0)
		avg_locality_total = global_total_locality / global_flow_blocks;

	printf("         Total avg locality = %.2f, global max = %lu, total packets = %lu\n",
	       avg_locality_total,
	       global_max_locality,
	       global_packets);

	double total_avg = global_avg_sum / total_bursts;
	printf("Total average locality so far: %.2f (after %lu bursts)\n\n", total_avg, total_bursts);

	// save countmin in a file
	FILE *fp;
	fp = fopen("countmin.txt", "w");
	for (int i = 0; i < HASHFN_N; i++) {
		for (int j = 0; j < cms_columns; j++) {
			fprintf(fp, "%lu\n", cm->values[i][j]);
			// printf("%lu\n", cm->values[i][j]);
		}
	}
	fclose(fp);

	RTE_ETH_FOREACH_DEV(portid)
	{
		if ((cms_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	printf("Bye...\n");

	// free countmin
	for (int i = 0; i < HASHFN_N; i++) {
		rte_free(cm->values[i]);
	}
	rte_free(cm->values);
	rte_free(cm);

	return ret;
}
