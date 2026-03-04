/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include "rte_ethdev_driver.h"
#include "rte_pmd_qdma.h"
#include "xxhash64.h"
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
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_random.h>
#include <rte_string_fns.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <time.h>
#define abs(x) ((x) < 0 ? -(x) : (x))

struct qdma_rx_queue {
	struct rte_mempool	*mb_pool; /**< mbuf pool to populate RX ring. */
	void			*rx_ring; /**< RX ring virtual address */
	union qdma_ul_st_cmpt_ring	*cmpt_ring;
	struct wb_status	*wb_status;
	struct rte_mbuf		**sw_ring; /**< address of RX software ring. */
	struct rte_eth_dev	*dev;

	uint16_t		rx_tail;
};

uint64_t get_desc(struct rte_eth_dev *dev, uint16_t qid, int desc_idx);
uint16_t get_cidx(void *rx_queue);

int qdma_bypass_reg_get_prefetch_tag(void *dev_hndl, uint16_t qid,
                                     uint32_t *tag);
int qdma_write_queue_bypass_registers(void *dev_hndl, uint16_t qid, uint64_t addr, uint32_t tag, uint8_t valid, uint32_t num_desc);
int qdma_read_queue_bypass_registers(void *dev_hndl, uint16_t qid, uint64_t *addr, uint32_t *tag, uint8_t *valid, uint32_t *num_desc);
int qdma_bypass_clear_counters(void *dev_hndl);
int qdma_write_bypass_reg_debug(void *dev_hndl, uint8_t debug);
uint32_t qdma_reg_read(void *dev_hndl, uint32_t reg_offst);
uint32_t qdma_reg_read_usr(void *dev_hndl, uint32_t reg_offst);
void qdma_reg_write(void *dev_hndl, uint32_t reg_offst, uint32_t val);
void qdma_reg_write_usr(void *dev_hndl, uint32_t reg_offst, uint32_t val);
int rearm_c2h_ring_bypass(void* rxq);
int rearm_c2h_ring_bypass_tx(void* rxq, void* txq);
void print_phys(struct rte_eth_dev *dev, uint16_t qid);
uint16_t qdma_xmit_pkts_bypass(void* txq, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
void print_c2h_ring_status(void *rxqueue);

struct rte_eth_dev *dev=NULL;
uint16_t pending;
uint32_t prefetch_tag[2048];
uint32_t qmask=0x7;
  
/* PCAP file format structures */
typedef struct {
  uint32_t magic_number;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
} pcap_file_header_t;

typedef struct {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
} pcap_packet_header_t;

static FILE *pcap_file = NULL;

/* Initialize PCAP file for writing */
static int pcap_file_open(const char *filename) {
  pcap_file_header_t file_hdr = {
      .magic_number = 0xa1b2c3d4, /* PCAP magic number */
      .version_major = 2,
      .version_minor = 4,
      .thiszone = 0,
      .sigfigs = 0,
      .snaplen = 65535, /* Maximum packet size */
      .network = 1,     /* Ethernet */
  };

  pcap_file = fopen(filename, "wb");
  if (pcap_file == NULL) {
    printf("Error opening PCAP file: %s\n", filename);
    return -1;
  }

  if (fwrite(&file_hdr, sizeof(pcap_file_header_t), 1, pcap_file) != 1) {
    printf("Error writing PCAP file header\n");
    fclose(pcap_file);
    pcap_file = NULL;
    return -1;
  }

  fflush(pcap_file);
  return 0;
}

/* Write a packet to PCAP file */
static int pcap_write_packet(const uint8_t *packet_data, uint32_t packet_len) {
  pcap_packet_header_t pkt_hdr;
  struct timespec ts;

  if (pcap_file == NULL)
    return -1;

  /* Get current timestamp */
  clock_gettime(CLOCK_REALTIME, &ts);

  pkt_hdr.ts_sec = ts.tv_sec;
  pkt_hdr.ts_usec = ts.tv_nsec / 1000;
  pkt_hdr.incl_len = packet_len;
  pkt_hdr.orig_len = packet_len;

  /* Write packet header */
  if (fwrite(&pkt_hdr, sizeof(pcap_packet_header_t), 1, pcap_file) != 1) {
    printf("Error writing PCAP packet header\n");
    return -1;
  }

  /* Write packet data */
  if (fwrite(packet_data, packet_len, 1, pcap_file) != 1) {
    printf("Error writing PCAP packet data\n");
    return -1;
  }

  return 0;
}

/* Close PCAP file */
static void pcap_file_close(void) {
  if (pcap_file != NULL) {
    fflush(pcap_file);
    fclose(pcap_file);
    pcap_file = NULL;
  }
}

#define QDMA_BYPASS_REG_TABLE 0x5400
#define QDMA_BYPASS_REG_TABLE_PAGE_INDEX 0x5FF0

/* update cidx */
static void update_cidx(void *dev, uint16_t qid, uint16_t cidx, uint32_t tag) {
  
  // Use the qid as the page index 
	qdma_reg_write_usr(dev,QDMA_BYPASS_REG_TABLE_PAGE_INDEX,(uint32_t)(qid & 0x0FFFF));

  // Write  cidx, valid, tag
  uint32_t val = (cidx<<8) | (0x1 << 7) | (tag & 0x3F);
  qdma_reg_write_usr(dev, QDMA_BYPASS_REG_TABLE+12, val);

} 

/* Read pidx */
static uint32_t get_bypass_pidx(void *dev, uint16_t qid) {
  
  // Use the qid as the page index 
	qdma_reg_write_usr(dev,QDMA_BYPASS_REG_TABLE_PAGE_INDEX,(uint32_t)(qid & 0x0FFFF));

  // Read  pidx
  return qdma_reg_read_usr(dev, QDMA_BYPASS_REG_TABLE+16);
  
} 

static uint32_t get_bypass_cidx(void *dev, uint16_t qid) {
  
  // Use the qid as the page index 
	qdma_reg_write_usr(dev,QDMA_BYPASS_REG_TABLE_PAGE_INDEX,(uint32_t)(qid & 0x0FFFF));

  // Read  pidx
  uint32_t val =qdma_reg_read_usr(dev, QDMA_BYPASS_REG_TABLE+12);
  return (val >> 8) & 0x0FFFF;
  
} 


struct rte_eth_stats stats;
uint16_t port_id = 0;
#define HASHFN_N 40
#define COLUMNS 1048576
// #define COLUMNS 1024
struct countmin {
  uint64_t **values;
};

struct countmin *cm;

static volatile bool force_quit;
bool silent = false;
bool dump = false;
bool bypass = false;
uint8_t freerunning = 0; /* cmpt overflow check mode: 0=disabled, 1=enabled */
bool debug = false;
bool retransmit = false;
uint64_t phys_addr;

/* MAC updating disabled by default */
static int mac_updating = 0;

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
  uint16_t port[NUM_PORTS];
} __rte_cache_aligned;

static struct port_pair_params port_pair_params_array[RTE_MAX_ETHPORTS / 2];
static struct port_pair_params port_pair_params_array[RTE_MAX_ETHPORTS / 2];
static struct port_pair_params *port_pair_params;
static uint16_t nb_port_pair_params;
static uint16_t nb_port_pair_params;

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
                    .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP,
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
struct cms_port_statistics port_statistics[RTE_MAX_ETHPORTS]
                                          [MAX_RX_QUEUE_PER_LCORE];

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 1; /* default period is 1 second */

uint64_t debug_error=0;
uint64_t cmpl_error=0;
uint64_t cmpl_error_seq=0;
uint64_t prev_debug_error=0;
uint64_t cmpl_error_dup=0;
uint64_t prev_cmpl_error=0;
uint64_t prev_cmpl_error_seq=0;
uint64_t prev_cmpl_error_dup=0;
uint32_t spin_time = 0;
uint32_t miss = 0;
uint32_t total = 0;
uint32_t empty = 0;
uint16_t sw_pkt_id = 1; /* Global software packet ID (works with 1 queue, used to detect packet loss */
uint16_t sw_debug_id[2048] = {0}; /* software packet ID for each queue, used to detect packet loss */

bool aggressive = false; /* aggressive mode disabled by default */
static unsigned prefetch_distance =
    4;                          /* prefetch distance for mbufs in burst */
uint32_t cms_columns = COLUMNS; /* number of columns in the count-min sketch */
/* Print out statistics on packets dropped */
uint64_t measured_packets_rx = 0;

uint64_t measured_tick = 0;
uint64_t rx_pkt_prev=0;
  
static void print_stats(void) {
  uint64_t total_packets_dropped = 0, total_packets_tx = 0,
           total_packets_rx = 0;
  static uint64_t total_packets_tx_prev = 0, total_packets_rx_prev = 0,
                  total_packets_dropped_prev = 0;

  unsigned portid;

  /* Static variables to store previous statistics */
  static uint64_t prev_tx[RTE_MAX_ETHPORTS][MAX_RX_QUEUE_PER_LCORE] = {0};
  static uint64_t prev_rx[RTE_MAX_ETHPORTS][MAX_RX_QUEUE_PER_LCORE] = {0};
  static uint64_t prev_dropped[RTE_MAX_ETHPORTS][MAX_RX_QUEUE_PER_LCORE] = {0};

  const char clr[] = {27, '[', '2', 'J', '\0'};
  const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

  /* Clear screen and move to top left */
  printf("%s%s", clr, topLeft);

  printf("\nPort statistics ====================================");

  for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
    /* skip disabled ports */
    if ((cms_enabled_port_mask & (1 << portid)) == 0)
      continue;

    for (uint32_t q = 0; q < cms_rx_queue_per_lcore; q++) {

      uint64_t diff_tx = port_statistics[portid][q].tx - prev_tx[portid][q];
      uint64_t diff_rx = port_statistics[portid][q].rx - prev_rx[portid][q];
      uint64_t diff_dropped =
          port_statistics[portid][q].dropped - prev_dropped[portid][q];

      if (!(diff_tx == 0 && diff_rx == 0 && diff_dropped == 0)) {
        
      printf("\nStatistics for port %u queue: %d ------------------------------"
             "\nPackets sent:     %'20llu (diff: %'llu)"
             "\nPackets received: %'20llu (diff: %'llu)"
             "\nPackets dropped:  %'20llu (diff: %'llu)\n",
             portid, q, (unsigned long long)port_statistics[portid][q].tx,
             (unsigned long long)diff_tx,
             (unsigned long long)port_statistics[portid][q].rx,
             (unsigned long long)diff_rx,
             (unsigned long long)port_statistics[portid][q].dropped,
             (unsigned long long)diff_dropped);
      }

      total_packets_dropped += port_statistics[portid][q].dropped;
      total_packets_tx += port_statistics[portid][q].tx;
      total_packets_rx += port_statistics[portid][q].rx;
      /* Update previous statistics */
      prev_tx[portid][q] = port_statistics[portid][q].tx;
      prev_rx[portid][q] = port_statistics[portid][q].rx;
      prev_dropped[portid][q] = port_statistics[portid][q].dropped;

    }
  }
  printf(
      "\nAggregate statistics ==============================="
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
  printf("miss: %u\n", miss);
  printf("empty: %u\n", empty);
  printf("total: %u\n", total);
  if (aggressive)
    printf("With aggressive policy\n");
  else
    printf("Without aggressive policy\n");
  if (bypass)
    printf("With bypass\n");
  else
    printf("Without bypass\n");
  if (debug)
    printf("With debug\n");
  else
    printf("Without debug\n");
  if (retransmit)
    printf("With retransmission\n");
  else
    printf("Without retransmission\n");
  if (freerunning)
    printf("With freerunning cmpt overflow check\n");
  else
    printf("Without freerunning cmpt overflow check\n");

  if (cms_rx_queue_per_lcore==1) {
    printf("Completion errors: %lu (diff:%'ld)\n", cmpl_error, cmpl_error - prev_cmpl_error);
    printf("Seq Completion errors: %lu (diff:%'ld)\n", cmpl_error_seq, cmpl_error_seq - prev_cmpl_error_seq);
    printf("Dup Completion errors: %lu (diff:%'ld)\n", cmpl_error_dup, cmpl_error_dup - prev_cmpl_error_dup);
  }
  if (debug) printf("Debug errors: %lu (diff:%'ld)\n", debug_error, debug_error - prev_debug_error);
  
  prev_cmpl_error=cmpl_error;
  prev_cmpl_error_seq=cmpl_error_seq;
  prev_cmpl_error_dup=cmpl_error_dup;
  prev_debug_error=debug_error;
  /*if (cms_rx_queue_per_lcore>1)
	  for (int q=0; q<2; q++) {
		  printf("==========Q=%d=========\n",q);
		  print_c2h_ring_status((void*)dev->data->rx_queues[q]);
	  }
  */    
  uint32_t full_counter= qdma_reg_read_usr(dev,0x514C);
  
  printf("full_counter: %u\n",full_counter);    
  printf("full_counter+received: %'12lu\n",full_counter+measured_packets_rx);    

  
  printf("\n====================================================\n");
  
  for (int q=0; q<2; q++) {
	  uint32_t pidx = get_bypass_pidx(dev, q) % 1024;
	  uint32_t cidx = get_bypass_cidx(dev, q);

	  printf("BYPASS (%d) pidx: %u, cidx: %u",q, pidx, cidx);
	  if (pidx==cidx) printf("  (EMPTY) ");
	  printf("\n");
  }


  printf("\n====================================================\n");
  
  printf("pending: %u\n",pending);  
  measured_tick++;
  uint32_t val_l = qdma_reg_read_usr(dev,0xB020);
  uint32_t val_h = qdma_reg_read_usr(dev,0xB024);
  uint64_t rx_pkt = ((uint64_t)val_h <<32) | val_l;
  printf("packets on q=0 : %'14lu\n",port_statistics[0][0].rx);
  printf("packets on q=1 : %'14lu\n",port_statistics[0][1].rx);
  printf("packets on q=2 : %'14lu\n",port_statistics[0][2].rx);
  printf("packets on q=3 : %'14lu\n",port_statistics[0][3].rx);

  printf("Packet Adapter received packets: %ld (diff: %'14ld)\n", rx_pkt, rx_pkt-rx_pkt_prev);  
  rx_pkt_prev = rx_pkt;
  uint32_t rx_pkt2 = qdma_reg_read_usr(dev,0x512C)-1; // start from 1 to sync with CMPL id
  printf("QDMA Subsystem received packets: %d\n", rx_pkt2);  
  printf("diff: %lu\n", rx_pkt-rx_pkt2);    
  
  printf("prefetch distance: %u\n", prefetch_distance);
  printf("\n====================================================\n");
  
  /* Reset previous statistics */
  total_packets_tx_prev = total_packets_tx;
  total_packets_rx_prev = total_packets_rx;
  total_packets_dropped_prev = total_packets_dropped;

  if (rte_eth_stats_get(port_id, &stats) < 0) {
    printf("Error getting stats for port %u\n", port_id);
  }
  fflush(stdout);
}

static void cms_mac_updating(struct rte_mbuf *m, unsigned dest_portid) {
  struct rte_ether_hdr *eth;
  void *tmp;

  eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

  /* 02:00:00:00:00:xx */
  tmp = &eth->d_addr.addr_bytes[0];
  tmp = &eth->d_addr.addr_bytes[0];
  *((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dest_portid << 40);

  /* src addr */
  rte_ether_addr_copy(&cms_ports_eth_addr[dest_portid], &eth->s_addr);
}

static void count_add(struct rte_mbuf *m) {
  struct rte_ether_hdr *eth;
  eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
  uint32_t src_ip = 0, dst_ip = 0;
  uint16_t src_port = 0, dst_port = 0;
  uint8_t proto = 0;
  // parse the packet
  if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth + 1);
    src_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
    dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
    proto = ipv4_hdr->next_proto_id;
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
    }
  } else {
    return; // not IPv4
  }
  // --- costruisci la 5-tuple in un buffer continuo ---
  struct five_tuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
  } __attribute__((packed));

  struct five_tuple key = {
      .src_ip = src_ip,
      .dst_ip = dst_ip,
      .src_port = src_port,
      .dst_port = dst_port,
      .proto = proto,
  };

  // --- calcolo hash sui campi della 5-tuple ---
  for (int i = 0; i < HASHFN_N; i++) {
    uint64_t h = xxhash64((const char *)&key, sizeof(key), i);
    uint32_t target_idx = h & (cms_columns - 1);
    cm->values[i][target_idx]++;
  }
}

static void cms_simple_forward(struct rte_mbuf *m, unsigned portid) {
  unsigned dst_port;
  int sent;
  struct rte_eth_dev_tx_buffer *buffer;

  dst_port = cms_dst_ports[portid];

  if (mac_updating)
    cms_mac_updating(m, dst_port);

  buffer = tx_buffer[dst_port];
  sent = rte_eth_tx_buffer(dst_port, 0, buffer, m);
  if (sent)
    port_statistics[dst_port][0].tx += sent;
}
uint64_t end_time = 0;
/* main processing loop */
static void cms_main_loop(void) {
  struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
  struct rte_mbuf *m;
  int sent;
  unsigned lcore_id;
  uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
  unsigned i, j, portid, nb_rx;
  struct lcore_queue_conf *qconf;
  const uint64_t drain_tsc =
      (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
  struct rte_eth_dev_tx_buffer *buffer;

  prev_tsc = 0;
  timer_tsc = 0;

  lcore_id = rte_lcore_id();
  qconf = &lcore_queue_conf[lcore_id];
  dev = &rte_eth_devices[0];
				    
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

  uint16_t debug_counter_prev = 255;
  uint16_t pktid_prev = 255;
			    
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
        sent = rte_eth_tx_buffer_flush(portid, 0, buffer);
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
            if (!silent)
              print_stats();
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
    int max_loops = 100;
    for (int l = 0; l < 100; l++)
	    for (i = 0; i < qconf->n_rx_port; i++) {
		    portid = qconf->rx_port_list[i];
		    for (uint32_t q = 0; q < cms_rx_queue_per_lcore; q++) {
          if (bypass && retransmit) {
            rearm_c2h_ring_bypass_tx(dev->data->rx_queues[q],dev->data->tx_queues[q]);
            uint16_t cidx = get_cidx(dev->data->rx_queues[q]);
            update_cidx(dev, q, cidx, prefetch_tag[q & qmask]); // update cidx to rearm the ring
          }
          nb_rx = rte_eth_rx_burst(portid, q, pkts_burst, MAX_PKT_BURST);

			    port_statistics[portid][q].rx += nb_rx;

			    for (j = 0; j < nb_rx; j++) {
				    total++;
				    m = pkts_burst[j];
            uint16_t pkid = m->timesync; // using timesync field to store packet ID for simplicity: global (not per queue) packet counter
            if ((sw_pkt_id !=pkid) && (cms_rx_queue_per_lcore==1)) {
              /* 
              printf("----------------------------------------------------\n");
              printf("---               Completion error               ---\n");
              printf("total: %u\n", total);
              printf("Packet ID mismatch! Expected: %u, Actual: %u diff:%d\n", sw_pkt_id, pkid,pkid-sw_pkt_id); 
              printf("pktid: %d\n", pkid);
              printf("pktid_prev: %d\n", pktid_prev);
              printf("completion error: %lu\n",cmpl_error);
              printf("----------------------------------------------------\n");
              */
              cmpl_error++;
              sw_pkt_id = pkid; // resync software packet ID to avoid cascading errors
            }
            //debug_counter_prev = debug_counter;
            if (pkid == pktid_prev) cmpl_error_dup++;
            if (pkid != (pktid_prev + 1) && (pkid != 0) && (pkid != pktid_prev)) {
              cmpl_error_seq++;
              /*
              printf("lost completion entry\n");
              printf("pktid: %d\n", pkid);
              printf("pktid_prev: %d\n", pktid_prev);*/
            }

	          if (debug) {
              uint32_t pkt_len = rte_pktmbuf_pkt_len(m);
              int64_t payload_id= *(uint32_t*)((uint8_t*)rte_pktmbuf_mtod(m, void *)+31);
              uint32_t payload_counter= *(uint32_t*)((uint8_t*)rte_pktmbuf_mtod(m, void *)+35);
              uint16_t qid= *(uint16_t*)((uint8_t*)rte_pktmbuf_mtod(m, void *)+26);
              if (qid!=q) {
                printf("----------------------------------------------------\n");
                printf("Debug: Queue ID mismatch! Expected: %d, Actual: %d\n", q, qid);
                printf("----------------------------------------------------\n");
              }
              if (pkt_len > 64) {
                payload_id= *(uint32_t*)((uint8_t*)rte_pktmbuf_mtod(m, void *)+95);
                payload_counter= *(uint32_t*)((uint8_t*)rte_pktmbuf_mtod(m, void *)+99);
              }
					    payload_id= payload_id & 0x0FFFF; // mask to 16 bits
              if ((((payload_id+1)& 0x0FFFF) != sw_debug_id[q]) && (payload_id != sw_debug_id[q])) {
                debug_error++;
                
                printf("----------------------------------------------------\n");
                printf("Debug: Pkt ID mismatch! Payload: %ld, counted: %d diff: %ld\n", payload_id, sw_debug_id[q], (payload_id - sw_debug_id[q]) & 0x0FFFF);
                printf("debug error: %lu\n",debug_error);
                printf("completion error: %lu\n",cmpl_error);
                printf("total: %u\n",total);
                printf("----------------------------------------------------\n");
                
                sw_debug_id[q] = payload_id; // resync software packet ID to avoid cascading errors
              }
              if ((pkid+cmpl_error  &0x0FFFF) != (payload_counter &0x0FFFF)) {
                printf("Debug: Packet ID mismatch between CMPL id and payload counter: payload_id: %u pkid:%d,  diff: %u\n", payload_counter &0x0FFFF, pkid, (payload_counter & 0x0FFFF)- pkid);
                printf("debug error: %lu\n",debug_error);
                printf("completion error: %lu\n",cmpl_error);
                printf("pktid: %d\n", pkid);
                printf("pktid_prev: %d\n", pktid_prev);
                printf("total: %u\n",total);
                printf("----------------------------------------------------\n");
              }
              
              int64_t debug_addr= *(int64_t*) ((uint8_t*)rte_pktmbuf_mtod(m, void *)+14);
              char flag= *(char*)((uint8_t*)rte_pktmbuf_mtod(m, void *)+30);
              char tag= *(char*)((uint8_t*)rte_pktmbuf_mtod(m, void *)+28);
					    /*printf("----------------------------------------------------\n");
					    printf("From queue: %d \n", q);
              printf("Payload addr: %p --", (void*)debug_addr);
					    printf("pkt_cnt=%u Packet ID: %ld\n", total, payload_id);
					    printf("tag=%d qid: %d\n", tag, qid);
					    printf("flag=0x%02x \n", flag);
					    printf("----------------------------------------------------\n");
              */
					    if (debug_addr != (int64_t) rte_pktmbuf_mtod(m, void *)) {
						    printf("----------------------------------------------------\n");
						    printf("pkt_cnt=%u Packet ID: %ld\n", total, payload_id);
						    printf("Debug: Packet data address mismatch! Expected (phys_addr): %p, Actual (from payload): %p --", (void*)rte_pktmbuf_mtod(m, void *), (void*)debug_addr);
						    printf("Diff %ld (%ld)\n", debug_addr-(int64_t)rte_pktmbuf_mtod(m, void *),abs(debug_addr-(int64_t)rte_pktmbuf_mtod(m, void *))/2368);
						    printf("----------------------------------------------------\n");
					    }
              

				    }
            pktid_prev = pkid;
            sw_debug_id[q]++;
            sw_pkt_id++;

				    /*printf("primo:\n");
				      for (size_t i = 0; i < 32; i++) {
				      printf("%X ", *(((uint8_t *)phys_addr) + i));
				      }
				      printf("\n");

				      printf("secondo:\n");
				      for (size_t i = 0; i < 32; i++) {
				      printf("%X ", *(((uint8_t *)phys_addr) -2368+ i));
				      }
				      printf("\n");

				      printf("terzo:\n");
				      for (size_t i = 0; i < 32; i++) {
				      printf("%X ", *(((uint8_t *)phys_addr) -2*2368+ i));
				      }
				      printf("\n");

				      printf("i-esimo:\n");
				      for (size_t i = 0; i < 32; i++) {
				      printf("%X ", *(((uint8_t *)phys_addr) -(total %128)*2368+ i));
				      }
				      printf("\n");

				      printf("cinquanta:\n");
				      for (size_t i = 0; i < 32; i++) {
				      printf("%X ", *(((uint8_t *)phys_addr) -50*2368+ i));
				      }
				      printf("\n");
				      */

				    // printf("lcore %u: port %u, queue %d, packet %d\n", lcore_id,
				    // portid, q, j);
				    // rte_prefetch0(rte_pktmbuf_mtod(m, void *));
				    if ((prefetch_distance > 0) && (j + prefetch_distance < nb_rx)) {
					    rte_prefetch0(
							    rte_pktmbuf_mtod(pkts_burst[j + prefetch_distance], void *));
				    }

				    /* Write packet to PCAP file */
				    if (pcap_file != NULL) {
					    uint8_t* pkt_data = (uint8_t*)rte_pktmbuf_mtod(m, uint8_t *);
					    //printf("Packet data address (%ld): %p --", total,pkt_data);
					    uint32_t pkt_len = rte_pktmbuf_pkt_len(m);
					    //printf("Packet data: %c%c%c%c\n",pkt_data[pkt_len-4],pkt_data[pkt_len-3],pkt_data[pkt_len-2],pkt_data[pkt_len-1]);
					    pcap_write_packet(pkt_data, pkt_len);
				    }
				    //count_add(m);
				    //cms_simple_forward(m, portid);

            if (!bypass) {
              if (retransmit) {
                cms_simple_forward(m, portid); 
              } else {
                rte_pktmbuf_free(m);
              }
            }
				    measured_packets_rx++;
			    }
			    //TX burst
          if (bypass && retransmit && nb_rx > 0) {
            port_statistics[0][q].tx += qdma_xmit_pkts_bypass(dev->data->tx_queues[q], pkts_burst, nb_rx);
          }
          
          // rearm!
          if (bypass && !retransmit && (nb_rx > 0)) {
               rearm_c2h_ring_bypass((void*)dev->data->rx_queues[q]);
               uint16_t cidx = get_cidx(dev->data->rx_queues[q]);
               update_cidx(dev, q, cidx, prefetch_tag[q & qmask]); // update cidx to rearm the ring
          }
          
          if (aggressive && nb_rx == MAX_PKT_BURST && max_loops > 0) {
				    q--; // if we got MAX_PKT_BURST packets, we need to process them again
				    max_loops--;
			    } 
          else 
				    max_loops = 100;

			    if (nb_rx < MAX_PKT_BURST) {
				    spin_time++;
			    }
			    if (nb_rx == 0) {
				    empty++;
			    }
		    }
	    }
  }
}

static int cms_launch_one_lcore(void *arg) {
  cms_main_loop();
  return 0;
}

/* display usage */
static void cms_usage(const char *prgname) {
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

static int cms_parse_portmask(const char *portmask) {
  char *end = NULL;
  unsigned long pm;

  /* parse hexadecimal string */
  pm = strtoul(portmask, &end, 16);
  if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
    return 0;

  return pm;
}

static int cms_parse_port_pair_config(const char *q_arg) {
  enum fieldnames { FLD_PORT1 = 0, FLD_PORT2, _NUM_FLD };
  unsigned long int_fld[_NUM_FLD];
  const char *p, *p0 = q_arg;
  char *str_fld[_NUM_FLD];
  unsigned int size;
  char s[256];
  char *end;
  int i;

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
      errno = 0;
      int_fld[i] = strtoul(str_fld[i], &end, 0);
      if (errno != 0 || end == str_fld[i] || int_fld[i] >= RTE_MAX_ETHPORTS)
        return -1;
    }
    if (nb_port_pair_params >= RTE_MAX_ETHPORTS / 2) {
      printf("exceeded max number of port pair params: %hu\n",
             nb_port_pair_params);
      return -1;
    }
    port_pair_params_array[nb_port_pair_params].port[0] =
        (uint16_t)int_fld[FLD_PORT1];
    port_pair_params_array[nb_port_pair_params].port[1] =
        (uint16_t)int_fld[FLD_PORT2];
    ++nb_port_pair_params;
  }
  port_pair_params = port_pair_params_array;
  return 0;
}

static unsigned int cms_parse_nqueue(const char *q_arg) {
  char *end = NULL;
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

static const char short_options[] = "c:" /* columns  */
                                    "Q"  /* silent */
                                    "D"  /* dump pcap */
                                    "B"  /* enable bypass */
                                    "x"  /* enable debug */
                                    "a"  /* aggressive */
                                    "T" /* enable retransmit */
                                    "F" /* enable freerunning */        
                                    "P:" /* portmask  */
                                    "q:" /* number of queues */
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
static int cms_parse_args(int argc, char **argv) {
  int opt, ret;
  char **argvopt;
  int option_index;
  char *prgname = argv[0];

  argvopt = argv;
  argvopt = argv;
  port_pair_params = NULL;

  while ((opt = getopt_long(argc, argvopt, short_options, lgopts,
                            &option_index)) != EOF) {
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
    case 'Q':
      silent = true;
      break;
    case 'D':
      dump = true;
      break;
    case 'B':
      bypass = true;
      break;
    case 'x':
      debug = true;
      break;
    case 'T':
      retransmit=true;
      break;
    case 'F':  
      freerunning = 1;
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
  ret = optind - 1;
  ret = optind - 1;
  optind = 1; /* reset getopt lib */
  return ret;
}

/*
 * Check port pair config with enabled port mask,
 * and for valid port pair combinations.
 */
static int check_port_pair_config(void) {
  uint32_t port_pair_config_mask = 0;
  uint32_t port_pair_mask = 0;
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
static void check_all_ports_link_status(uint32_t port_mask) {
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
  uint16_t portid;
  uint8_t count, all_ports_up, print_flag = 0;
  struct rte_eth_link link;
  int ret;
  char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

  printf("\nChecking link status");
  fflush(stdout);
  for (count = 0; count <= MAX_CHECK_TIME; count++) {
    if (force_quit)
      return;
    all_ports_up = 1;
    RTE_ETH_FOREACH_DEV(portid) {
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

static void signal_handler(int signum) {
  if (signum == SIGINT || signum == SIGTERM) {
    printf("\n\nSignal %d received, preparing to exit...\n", signum);
    /*for (uint32_t qid = 0; qid < cms_rx_queue_per_lcore; qid++) { 
        uint64_t r_addr;
        uint32_t r_tag;
        uint8_t r_valid;
        uint32_t r_num_desc;
        qdma_read_queue_bypass_registers(dev, qid, &r_addr, &r_tag, &r_valid, &r_num_desc);
        printf("q=%d addr: %lx tag:%u valid:%u desc:%u\n",qid,r_addr,r_tag,r_valid,r_num_desc);
      }*/
    
    force_quit = true;
  }
  if(signum == SIGQUIT) {
    //qdma_inv_rx_queue_ctxts(dev,0,1); 
    //qdma_clr_rx_queue_ctxts(dev,0,1); 
    //rearm_c2h_ring_bypass((void*)dev->data->rx_queues[0]);
    /*uint16_t rx_cmpt_tail= get_cidx(dev->data->rx_queues[0]);
    printf("Current RX completion tail: %u\n", rx_cmpt_tail);
    int32_t val= qdma_reg_read(dev,0x1800C);
	  val &= 0xffff0000; 
	  val += rx_cmpt_tail; 
	  qdma_reg_write(dev,0x1800C,val);
	  rte_wmb();
	  val= qdma_reg_read(dev,0x1800C);
    printf("cidx: %d\n",val &0x0ffff);*/
    uint16_t cidx = get_cidx(dev->data->rx_queues[0]);
    update_cidx(dev, 0, cidx, prefetch_tag[0]); // update cidx to rearm the ring
    printf("SIGQUIT received\n");
  }
}

int main(int argc, char **argv) {
  struct lcore_queue_conf *qconf;
  int ret;
  uint16_t nb_ports;
  uint16_t nb_ports_available = 0;
  uint16_t portid, last_port;
  unsigned lcore_id, rx_lcore_id;
  unsigned nb_ports_in_mask = 0;
  unsigned int nb_lcores = 0;
  unsigned int nb_mbufs;
    
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
  signal(SIGQUIT, signal_handler);

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
    rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
             (1 << nb_ports) - 1);

  /* reset cms_dst_ports */
  for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
    cms_dst_ports[portid] = 0;
  last_port = 0;

  /* populate destination port details */
  if (port_pair_params != NULL) {
    uint16_t idx, p;

    for (idx = 0; idx < (nb_port_pair_params << 1); idx++) {
      p = idx & 1;
      portid = port_pair_params[idx >> 1].port[p];
      cms_dst_ports[portid] = port_pair_params[idx >> 1].port[p ^ 1];
    }
  } else {
    RTE_ETH_FOREACH_DEV(portid) {
      /* skip ports that are not enabled */
      if ((cms_enabled_port_mask & (1 << portid)) == 0)
        continue;

      if (nb_ports_in_mask % 2) {
        cms_dst_ports[portid] = last_port;
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
  qconf = NULL;

  /* Initialize the port/queue configuration of each logical core */
  RTE_ETH_FOREACH_DEV(portid) {
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
    printf("Lcore %u: RX port %u TX port %u\n", rx_lcore_id, portid,
           cms_dst_ports[portid]);
  }

  nb_mbufs = RTE_MAX(
      cms_rx_queue_per_lcore * nb_ports *
          (nb_rxd + nb_txd + MAX_PKT_BURST + nb_lcores * MEMPOOL_CACHE_SIZE),
      8192U);
  printf("Creating mbuf pool with %u mbufs\n", nb_mbufs);

  /* create the mbuf pool */
  cms_pktmbuf_pool =
      rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs, MEMPOOL_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
/*
  cms_pktmbuf_pool = rte_mempool_create_empty("mbuf_pool",
     nb_mbufs,
       RTE_MBUF_DEFAULT_BUF_SIZE + sizeof(struct rte_mbuf), 
       MEMPOOL_CACHE_SIZE,
        sizeof(struct rte_pktmbuf_pool_private),
        SOCKET_ID_ANY,
        rte_socket_id() 
      );
  if (cms_pktmbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

  if (rte_mempool_set_ops_byname(cms_pktmbuf_pool, "stack", NULL) < 0) 
          rte_panic("mempool_set_ops stack failed\n");

  struct rte_pktmbuf_pool_private *priv =
    rte_mempool_get_priv(cms_pktmbuf_pool);

  priv->mbuf_data_room_size = RTE_MBUF_DEFAULT_BUF_SIZE;
  priv->mbuf_priv_size = 0;

  if (rte_mempool_populate_default(cms_pktmbuf_pool) < 0)
      rte_panic("mempool_populate_default failed\n");
 rte_mempool_obj_iter(cms_pktmbuf_pool, rte_pktmbuf_init, NULL);
      

  */
  /* Initialise each port */
  RTE_ETH_FOREACH_DEV(portid) {
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_conf local_port_conf = port_conf;
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
      rte_exit(EXIT_FAILURE, "Error during getting device (port %u) info: %s\n",
               portid, strerror(-ret));

    struct rte_eth_dev *dev = &rte_eth_devices[port_id];
    
    //qdma_reg_write_usr(dev,0x000C,1); //QDMA reset
    //qdma_reg_write_usr(dev,0x000C,2); //CMAC0 reset
    //qdma_reg_write_usr(dev,0x000C,4); //CMAC1 reset
    //rte_delay_ms(5000);

    // local_port_conf.rxmode.mq_mode              = ETH_MQ_RX_RSS;
    // local_port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP |
    // ETH_RSS_TCP | ETH_RSS_UDP;

    // modificare per mettere più code
    ret = rte_eth_dev_configure(portid, cms_rx_queue_per_lcore, cms_rx_queue_per_lcore,
                                &local_port_conf);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", ret,
               portid);

    // struct qdma_pci_dev *qdma_dev = dev->data->dev_private;
    uint32_t reg_offst = 0; // timestamp;
    uint32_t val = qdma_reg_read_usr(dev, reg_offst);
    // Timestamp--> QDMA Reg (0x0) Value: 0x28602ca
    // 29/01/2026 0xc5a366e
    printf("Timestamp--> QDMA Reg (0x%X) Value: 0x%X\n", reg_offst, val);
    uint32_t cfg_val = qdma_reg_read(
        dev, 0xBE0); // QDMA_CFG_OFFSET 0x001f0040 --> prefech cache size 64 OK!
    printf("CFG VAL: 0x%08x\n", cfg_val);

    
    struct rte_eth_rss_reta_entry64 reta_conf[2048 / RTE_RETA_GROUP_SIZE];
    int i, j;
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
      rte_exit(EXIT_FAILURE, "Cannot set RSS REA: err=%d, port=%u\n", ret,
               portid);

    rte_eth_dev_rss_reta_query(portid, reta_conf, dev_info.reta_size);
    cms_rx_queue_per_lcore = reta_conf[0].reta[0] + 1;
    printf("cms_rx_queue_per_lcore: %d\n", cms_rx_queue_per_lcore);

    rte_eth_dev_info_get(portid, &dev_info);

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
    if (ret < 0)
      rte_exit(EXIT_FAILURE,
               "Cannot adjust number of descriptors: err=%d, "
               "port=%u\n",
               ret, portid);

    ret = rte_eth_macaddr_get(portid, &cms_ports_eth_addr[portid]);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "Cannot get MAC address: err=%d, port=%u\n", ret,
               portid);

    int diag;
    uint32_t qid;
    uint32_t queue_base;
    diag = rte_pmd_qdma_get_queue_base(portid, &queue_base);
    if (diag < 0)
      rte_exit(EXIT_FAILURE, "rte_pmd_qdma_get_queue_base : Querying of "
                             "QUEUE_BASE failed\n");
    // for loop sulle varie code
    /* init one RX queue */
    fflush(stdout);
    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = local_port_conf.rxmode.offloads;

    for (qid = 0; qid < cms_rx_queue_per_lcore; qid++) {
      diag =
          rte_pmd_qdma_set_queue_mode(portid, qid, RTE_PMD_QDMA_STREAMING_MODE);
      if (diag < 0)
        rte_exit(EXIT_FAILURE, "rte_pmd_qdma_set_queue_mode : "
                               "Passing of STREAMING_MODE "
                               "failed qid=%d\n",qid);

      if (bypass) {
        rte_pmd_qdma_configure_rx_bypass(portid, qid, 2,
                                       0); // RTE_PMD_QDMA_RX_BYPASS_SIMPLE = 2,
        // Size 0 indicates internal mode descriptor size.
      } else {
        rte_pmd_qdma_configure_rx_bypass(portid, qid, 0,
                                       0); // RTE_PMD_QDMA_RX_BYPASS_NONE = 0,
      }
      ret = rte_eth_rx_queue_setup(portid, qid, nb_rxd,
                                   rte_eth_dev_socket_id(portid), &rxq_conf,
                                   cms_pktmbuf_pool);
      if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n", ret,
                 portid);

      ret = rte_pmd_qdma_set_cmpt_overflow_check(port_id, qid, !freerunning);      
      if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_pmd_qdma_set_cmpt_overflow_check:err=%d, port=%u\n", ret,
                 portid);    

      if (bypass && (qid <= qmask)) { 
        if (qdma_bypass_reg_get_prefetch_tag(dev, qid, &prefetch_tag[qid])) {
          printf("error reading prefetch tag\n");
          return -1;
        }
        prefetch_tag[qid] &= 0x7f;
        printf("Prefetch tag for qid=%d: %u\n", qid, prefetch_tag[qid]);
      }
      /* init one TX queuefor eacxh RX queue */
      fflush(stdout);
      txq_conf = dev_info.default_txconf;
      txq_conf.offloads = local_port_conf.txmode.offloads;
      ret = rte_eth_tx_queue_setup(portid, qid, nb_txd,
                                   rte_eth_dev_socket_id(portid), &txq_conf);
      if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n", ret,
                 portid);

      /* Initialize TX buffers */
      tx_buffer[portid] =
          rte_zmalloc_socket("tx_buffer", RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST),
                             0, rte_eth_dev_socket_id(portid));
      if (tx_buffer[portid] == NULL)
        rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
                 portid);

      rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

      ret = rte_eth_tx_buffer_set_err_callback(
          tx_buffer[portid], rte_eth_tx_buffer_count_callback,
          &port_statistics[portid][0].dropped);
      if (ret < 0)
        rte_exit(EXIT_FAILURE,
                 "Cannot set error callback for tx buffer on port %u\n",
                 portid);

      ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL, 0);
      if (ret < 0)
        printf("Port %u, Failed to disable Ptype parsing\n", portid);

      // end queue loop
    }
    /* Start device */
    ret = rte_eth_dev_start(portid);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", ret,
               portid);

    printf("done: \n");
    qdma_write_bypass_reg_debug(dev, 0);
    if (bypass) {
      qdma_reg_write_usr(dev,0x5150,qmask); //qmask
      //qdma_reg_write_usr(dev,0x5154,0); //dsc_crdt_in_fence
      for (qid = 0; qid < cms_rx_queue_per_lcore; qid++) { 
        //print_phys(dev, qid);
        phys_addr = get_desc(dev, qid, 0);
        printf("Phys addr %08lx\n", phys_addr);
        qdma_write_queue_bypass_registers(dev, qid, phys_addr, prefetch_tag[qid &qmask], 1, nb_rxd);
        if (debug) qdma_write_bypass_reg_debug(dev, 1); 
      }
      
      if (freerunning) {
        qdma_write_bypass_reg_debug(dev, 2); 
        if (debug) qdma_write_bypass_reg_debug(dev, 3); 
      }
      if (!bypass) 
	      qdma_write_bypass_reg_debug(dev, 2); 

      //qdma_write_bypass_reg_debug(dev, 2); 
      
      //reset counters
      qdma_bypass_clear_counters(dev);
      /*for (qid = 0; qid < cms_rx_queue_per_lcore; qid++) { 
        uint64_t r_addr;
        uint32_t r_tag;
        uint8_t r_valid;
        uint32_t r_num_desc;
        qdma_read_queue_bypass_registers(dev, qid, &r_addr, &r_tag, &r_valid, &r_num_desc);
        printf("q=%d addr: %lx tag:%u valid:%u desc:%u\n",qid,r_addr,r_tag,r_valid,r_num_desc);
      }*/
    }
    /*else {
      qdma_write_bypass_reg_valid(dev, 0);
    }*/


    printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n", portid,
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
    rte_exit(EXIT_FAILURE,
             "All available ports are disabled. Please set portmask.\n");
  }

  // start

  cm = rte_zmalloc(NULL, sizeof(struct countmin), 64);
  cm->values = rte_zmalloc(NULL, sizeof(uint64_t *) * HASHFN_N, 64);
  for (int i = 0; i < HASHFN_N; i++) {
    cm->values[i] = rte_zmalloc(NULL, sizeof(uint64_t) * cms_columns, 64);
  }

  for (int i = 0; i < HASHFN_N; i++) {
    for (uint32_t j = 0; j < cms_columns; j++) {
      cm->values[i][j] = 0;
    }
  }

  check_all_ports_link_status(cms_enabled_port_mask);

  /* Initialize PCAP file for packet capture */
  if (dump)
    if (pcap_file_open("captured_packets.pcap") < 0) {
      printf("Warning: Could not open PCAP file for writing\n");
    }

  ret = 0;
  /* launch per-lcore init on every lcore */
  rte_eal_mp_remote_launch(cms_launch_one_lcore, NULL, CALL_MAIN);
  RTE_LCORE_FOREACH_WORKER(lcore_id) {
    if (rte_eal_wait_lcore(lcore_id) < 0) {
      ret = -1;
      break;
    }
  }
  
  printf("packets: %u\n", total);
  printf("RX packets: %" PRIu64 "\n", stats.ipackets);
  printf("TX packets: %" PRIu64 "\n", stats.opackets);
  printf("RX dropped: %" PRIu64 "\n", stats.imissed);
  printf("measured RX packets: %.2f\n", (float)measured_packets_rx);
  printf("measured RX Throughput: %.2f\n",
         (double)measured_packets_rx /
             ((double)end_time / (double)rte_get_timer_hz()));
  printf("measured time: %.2f seconds\n",
         (double)end_time / (double)rte_get_timer_hz());
  
  struct rte_eth_dev *dev = &rte_eth_devices[0];
  int val=qdma_reg_read_usr(dev, 0x512C); // start from 1 to sync with CMPL id
  printf("PKT COUNTER VAL: %d\n", val);
  
  // save countmin in a file
  /*FILE *fp;
  fp = fopen("countmin.txt", "w");
  for (int i = 0; i < HASHFN_N; i++) {
    for (int j = 0; j < cms_columns; j++) {
      fprintf(fp, "%lu\n", cm->values[i][j]);
      // printf("%lu\n", cm->values[i][j]);
    }
  }
  fclose(fp);*/

  if (bypass) {
   for (uint32_t qid = 0; qid < cms_rx_queue_per_lcore; qid++) { 
        qdma_write_queue_bypass_registers(dev, qid, 0x0, 0, 0,0);
    }
  }

  RTE_ETH_FOREACH_DEV(portid) {
    if ((cms_enabled_port_mask & (1 << portid)) == 0)
      continue;
    printf("Closing port %d...", portid);
    ret = rte_eth_dev_stop(portid);
    if (ret != 0)
      printf("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);
    //rte_eth_dev_close(portid);
    printf(" Done\n");
  }
  printf("Bye...\n");

  /* Close PCAP file */
  if (dump)
    pcap_file_close();

  // free countmin
  for (int i = 0; i < HASHFN_N; i++) {
    rte_free(cm->values[i]);
  }
  rte_free(cm->values);
  rte_free(cm);

  return ret;
}
