/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include "drivers/net/qdma/rte_pmd_qdma.h"
#include "hashmap.h"
#include "load_balancer.h"
#include "nitrosketch/constants.h" // Include first
#include "nitrosketch/geometric.h"
#include "nitrosketch/minheap.h"
#include "nitrosketch/nitrosketch.h"
#include "nitrosketch/xxhash.h"
#include "ported-mica/hash.h"
#include "ported-mica/mehcached.h"
#include "r2p2_glue.h"
#include "rte_ethdev_driver.h"
#include "rte_pmd_qdma.h"
#include "xxhash64.h"
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <locale.h>
#include <netinet/in.h>
#include <netinet/udp.h>
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
#include <rte_errno.h>

#define CMD_LINE_OPT_MAC_UPDATING "mac-updating"
#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"
#define CMD_LINE_OPT_PORTMAP_CONFIG "portmap"
#define CMD_LINE_OPT_MICA_DB_SIZE "mica-db-size"
#define CMD_LINE_OPT_R2P2_IP "r2p2-ip"
#define CMD_LINE_OPT_R2P2_PORT "r2p2-port"
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */

#define QDMA_BYPASS_REG_TABLE 0x5400
#define QDMA_BYPASS_REG_TABLE_PAGE_INDEX 0x5FF0
#define RTE_LOGTYPE_DOL RTE_LOGTYPE_USER1
#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256
#define NUM_PORTS 2

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
#define MAX_RX_QUEUE 2048
#define MAX_TX_QUEUE_PER_PORT 2048

#define abs(x) ((x) < 0 ? -(x) : (x))

uint64_t get_desc(struct rte_eth_dev *dev, uint16_t qid, int desc_idx);
uint16_t get_cidx(void *rx_queue);
uint16_t get_cidx_tx(void *tx_queue, bool elastic);

int qdma_bypass_reg_get_prefetch_tag(void *dev_hndl, uint16_t qid,
                                     uint32_t *tag);

int qdma_write_queue_bypass_registers(void *dev_hndl, uint16_t qid,
                                      uint64_t addr, uint32_t tag,
                                      uint8_t valid, uint32_t num_desc);
int qdma_read_queue_bypass_registers(void *dev_hndl, uint16_t qid,
                                     uint64_t *addr, uint32_t *tag,
                                     uint8_t *valid, uint32_t *num_desc);

int qdma_read_direct_queue_bypass_registers(void *dev_hndl, uint16_t qid, uint64_t *addr, uint32_t *tag, uint8_t *valid, uint32_t *num_desc);
int qdma_write_direct_queue_bypass_registers(void *dev_hndl, uint16_t qid, uint64_t addr, uint32_t tag,  uint8_t valid, uint32_t num_desc);


int qdma_bypass_clear_counters(void *dev_hndl);
int qdma_bypass_direct_clear_counters(void *dev_hndl);
int qdma_write_bypass_reg_debug(void *dev_hndl, uint8_t debug);
uint32_t qdma_reg_read(void *dev_hndl, uint32_t reg_offst);
uint32_t qdma_reg_read_usr(void *dev_hndl, uint32_t reg_offst);
void qdma_reg_write(void *dev_hndl, uint32_t reg_offst, uint32_t val);
void qdma_reg_write_usr(void *dev_hndl, uint32_t reg_offst, uint32_t val);
void print_phys(struct rte_eth_dev *dev, uint16_t qid);
uint16_t qdma_xmit_pkts_bypass(void *txq, struct rte_mbuf **tx_pkts,
                               uint16_t nb_pkts);
uint16_t qdma_xmit_pkts(void *txq, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
void print_c2h_ring_status(void *rxqueue, void *txqueue);

struct countmin {
  uint64_t **values;
};

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

uint16_t prev_qid=0xffff;
rte_spinlock_t lock = RTE_SPINLOCK_INITIALIZER;
/* update cidx */
static void update_cidx(void *dev, uint16_t qid, uint16_t cidx, uint32_t tag) {

  // Use the qid as the page index
  if (prev_qid != qid) {
    qdma_reg_write_usr(dev, QDMA_BYPASS_REG_TABLE_PAGE_INDEX,
                       (uint32_t)(qid & 0x0FFFF));
    prev_qid = qid;
  }
  //qdma_reg_write_usr(dev, QDMA_BYPASS_REG_TABLE_PAGE_INDEX,
  //                   (uint32_t)(qid & 0x0FFFF));

  // Write  cidx, valid, tag
  uint32_t val = (cidx << 8) | (0x1 << 7) | (tag & 0x3F);
  qdma_reg_write_usr(dev, QDMA_BYPASS_REG_TABLE + 12, val);
}

/* update cidx */
static void update_direct_cidx(void *dev, uint16_t qid, uint16_t cidx, uint32_t tag) {

  // Write  cidx, valid, tag
  uint32_t val = (cidx << 8) | (0x1 << 7) | (tag & 0x3F);

  qdma_reg_write_usr(dev, qid*16+QDMA_BYPASS_REG_TABLE + 12, val);

}
/* update cidx */
static void update_direct2_cidx(void *dev, uint16_t qid, uint16_t cidx, uint32_t tag) {

  // Write  cidx, valid, tag
  uint32_t offset= (qid & 0x0f)*16+QDMA_BYPASS_REG_TABLE + 12;
  qid = qid >>4;
  uint32_t val = (qid <<24)| (cidx << 8) | (0x1 << 7) | (tag & 0x3F);
  qdma_reg_write_usr(dev, offset, val);
}

static void qdma_write_direct2_queue_bypass_registers(void *dev_hndl, uint16_t qid, uint64_t addr, uint32_t tag, uint8_t valid, uint32_t num_desc) {

        // Write the address
        qdma_reg_write_usr(dev_hndl,
                qid*16+QDMA_BYPASS_REG_TABLE,
                (uint32_t)(addr & 0xFFFFFFFF));
        qdma_reg_write_usr(dev_hndl,
                qid*16+QDMA_BYPASS_REG_TABLE + 4,
                (uint32_t)((addr >> 32) & 0xFFFFFFFF));
        // Write num desc
        qdma_reg_write_usr(dev_hndl,
                qid*16+QDMA_BYPASS_REG_TABLE + 8,
                num_desc);
	// Write tag and valid
	uint32_t offset= (qid & 0x0f)*16+QDMA_BYPASS_REG_TABLE + 12;
	qid = qid >>4;
	tag =  tag & 0x3F;
	tag =  valid ? (tag | (0x1 << 7)) : (tag & ~(0x1 << 7));
	uint16_t cidx=0;
	uint32_t val = (qid <<24)| (cidx << 8) | tag;
	qdma_reg_write_usr(dev_hndl, offset, val);
}

/* Read pidx */
static uint32_t get_bypass_pidx(void *dev, uint16_t qid) {

  // Use the qid as the page index
  qdma_reg_write_usr(dev, QDMA_BYPASS_REG_TABLE_PAGE_INDEX,
                     (uint32_t)(qid & 0x0FFFF));

  // Read  pidx
  return qdma_reg_read_usr(dev, QDMA_BYPASS_REG_TABLE + 16);
}

static uint32_t get_bypass_cidx(void *dev, uint16_t qid) {

  // Use the qid as the page index
  qdma_reg_write_usr(dev, QDMA_BYPASS_REG_TABLE_PAGE_INDEX,
                     (uint32_t)(qid & 0x0FFFF));

  // Read  pidx
  uint32_t val = qdma_reg_read_usr(dev, QDMA_BYPASS_REG_TABLE + 12);
  return (val >> 8) & 0x0FFFF;
}

struct rte_eth_dev *dev = NULL;
struct rte_eth_stats stats;

uint32_t qmask = 0x7;
uint32_t prefetch_tag[2048];

struct countmin *cm;
static volatile bool force_quit;
bool silent = false;
bool dump = false;
bool bypass = false;
bool lifo = false;
bool toasty = false;
bool shring = false;
uint8_t freerunning = 0; /* cmpt overflow check mode: 0=disabled, 1=enabled */
bool debug = false;
bool debug_timestamp = false;
bool elastic = false;
bool retransmit = false;
uint64_t phys_addr;
uint64_t end_time = 0;

uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
uint16_t rx_queue_per_core;

/* ethernet addresses of ports */
static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t enabled_port_mask = 0;

/* list of enabled ports */
static uint32_t dst_ports[RTE_MAX_ETHPORTS];

struct port_pair_params {

  uint16_t port[NUM_PORTS];
} __rte_cache_aligned;

static struct port_pair_params port_pair_params_array[RTE_MAX_ETHPORTS / 2];
static struct port_pair_params port_pair_params_array[RTE_MAX_ETHPORTS / 2];
static struct port_pair_params *port_pair_params;
static uint16_t nb_port_pair_params;
static uint16_t nb_port_pair_params;

static unsigned int rx_queue = 2;

struct lcore_queue_conf {
  unsigned n_rx_port;
  unsigned rx_port_list[MAX_RX_QUEUE];
  unsigned id;
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

struct rte_mempool *pktmbuf_pool[2048] = {NULL};
/* Per-port statistics struct */
struct port_statistics {
  uint64_t tx;
  uint64_t rx;
  uint64_t dropped;
} __rte_cache_aligned;
struct port_statistics port_stats[RTE_MAX_ETHPORTS][MAX_RX_QUEUE];

/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 1; /* default period is 1 second */

uint64_t q0_phys_addr_start;
uint64_t q1_phys_addr_start;
uint64_t debug_error = 0;
uint64_t cmpl_error = 0;
uint64_t cmpl_error_seq = 0;
uint64_t prev_debug_error = 0;
uint64_t cmpl_error_dup = 0;
uint64_t prev_cmpl_error = 0;
uint64_t prev_cmpl_error_seq = 0;
uint64_t prev_cmpl_error_dup = 0;
uint32_t miss = 0;
//uint32_t total = 0;
//uint16_t sw_pkt_id = 1; /* Global software packet ID (works with 1 queue, used
                          // to detect packet loss */
//uint32_t sw_debug_id[2048] = {1}; /* software packet ID for each queue, used to detect packet loss */

uint32_t prefetch_distance = 4; /* prefetch distance for mbufs in burst */
uint32_t cms_columns = 1048576; /* number of columns in the count-min sketch */
uint32_t num_hash = 4;
uint32_t num_rand = 0;
/* Print out statistics on packets dropped */


uint64_t measured_tick = 0;
uint64_t rx_pkt_prev = 0;

////////////// Application variables  ////////////////

/* MAC updating enabled by default */
int mac_updating_flag = 1;
int application = 0;

enum application_id {
  RX_COUNT = 0,
  L2_FWD = 1,
  COUNT_MIN_SKETCH = 2,
  MAGLEV = 3,
  NAT = 4,
  IDS = 5,
  DECRYPTION = 6,
  MICA = 7,
  NITROSKETCH = 8,
  MICA_UDP = 9,
  R2P2_ECHO = 10,
  R2P2_STSS = 11,
};

// NITROSKETCH
#ifdef NITRO_CMS
static CountMinSketch *nitro_cm;
#endif

#ifdef NITRO_CS
static CountSketch *nitro_cs;
#endif

// MICA
struct mehcached_table table_o;
struct mehcached_table *table;

// Number of distinct keys preloaded into the MICA table at startup (and,
// for process_mica(), cycled through on every packet). Runtime-configurable
// via --mica-db-size; see parse_args(). Must match what the traffic
// generator is told to use (same flag name), otherwise SETs for keys
// outside this range can fail once the table fills up.
static uint64_t mica_db_size = 2000;
static int VALUE_SIZE = 256;

// R2P2 (applications R2P2_ECHO=10, R2P2_STSS=11): local IP/port r2p2's
// protocol core reports to peers as its own address, so replies carry the
// right source IP:port. Configured via --r2p2-ip/--r2p2-port; see
// parse_args(). Stored already in network byte order (inet_addr()/htons())
// since that's the byte order process_r2p2() uses throughout for
// r2p2_host_tuple fields (matching the convention of r2p2's own DPDK
// backend).
static uint32_t r2p2_local_ip_be;
static uint16_t r2p2_local_port_be;
// Which port/queue the packet main_loop() is currently handing to
// process_packet() arrived on/should be replied on; __thread (not a
// plain global) because multiple lcores run main_loop() concurrently,
// each on its own port/queue. Set right before process_packet(m) below.
static __thread uint16_t r2p2_tx_portid;
static __thread uint16_t r2p2_tx_queue;

// process_mica_udp() wire opcodes: two independent GET/SET pairs, one per
// key/value size class.
//   "tiny"  : 8-byte key,  8-byte value
//   "small" : 16-byte key, 32-byte value
#define MICA_UDP_OP_GET_TINY 0
#define MICA_UDP_OP_SET_TINY 1
#define MICA_UDP_OP_GET_SMALL 2
#define MICA_UDP_OP_SET_SMALL 3

#define TINY_KEY_SIZE 8
#define TINY_VALUE_SIZE 8
#define SMALL_KEY_SIZE 16
#define SMALL_VALUE_SIZE 32

// Allocated in mica_table_init() once mica_db_size is known (after arg
// parsing).
static size_t *default_keys = NULL;
int keys_index = 0;

bool flag = false;

// ids
int dummy_count = 0;

// decryption
int decryption_key = 3;

// Maglev

char bkd_addr[MAX_BACKENDS][INET_ADDRSTRLEN];
int nbackends = 3;

struct hashmap services;
struct hashmap backends;
struct hashmap maglev_tables;
struct hashmap active_sessions;

static struct rte_mempool *
create_extbuf_pool(const char *name, uint16_t nb_ports,
                   uint16_t rx_queue, uint16_t nb_rxd,
                   uint16_t nb_txd, uint16_t nb_lcores, int socket_id) {
  uint32_t nb_mbuf;

  nb_mbuf = RTE_MAX(
      rx_queue * nb_ports *
          (nb_rxd + nb_txd + MAX_PKT_BURST + nb_lcores * MEMPOOL_CACHE_SIZE),
      8192U);

  const uint16_t data_room_size = RTE_MBUF_DEFAULT_BUF_SIZE;
  const uint16_t priv_size = 0;

  /* Total memory needed */
  size_t buf_len =
      RTE_ALIGN_CEIL(192 + data_room_size, RTE_CACHE_LINE_SIZE); // 2368 2176
  size_t total_size = (size_t)nb_mbuf * buf_len;

  /* Allocate contiguous DMA-safe memory */
  void *buf_addr = rte_malloc(NULL, total_size, RTE_CACHE_LINE_SIZE);
  if (!buf_addr) {
    rte_exit(EXIT_FAILURE, "Cannot allocate extbuf memory\n");
  }

  /* Get IOVA */
  rte_iova_t buf_iova = rte_malloc_virt2iova(buf_addr);
  if (buf_iova == RTE_BAD_IOVA) {
    rte_exit(EXIT_FAILURE, "IOVA translation failed\n");
  }

  /* Describe external memory region */
  struct rte_pktmbuf_extmem extmem = {
      .buf_ptr = buf_addr,
      .buf_iova = buf_iova,
      .buf_len = total_size,
      .elt_size = buf_len,
  };

  /* Create mempool */
  struct rte_mempool *mp = rte_pktmbuf_pool_create_extbuf(
      name, nb_mbuf, MEMPOOL_CACHE_SIZE, priv_size, data_room_size, socket_id,
      &extmem, 1 /* number of extmem segments */
  );

  if (mp == NULL) {
    rte_exit(EXIT_FAILURE, "Cannot create extbuf pool\n");
  }

  return mp;
}

static void print_stats(void) {
  uint64_t total_packets_dropped = 0, total_packets_tx = 0,
           total_packets_rx = 0;
  static uint64_t total_packets_tx_prev = 0, total_packets_rx_prev = 0,
                  total_packets_dropped_prev = 0;

  unsigned portid;

  /* Static variables to store previous statistics */
  static uint64_t prev_tx[RTE_MAX_ETHPORTS][MAX_RX_QUEUE] = {0};
  static uint64_t prev_rx[RTE_MAX_ETHPORTS][MAX_RX_QUEUE] = {0};
  static uint64_t prev_dropped[RTE_MAX_ETHPORTS][MAX_RX_QUEUE] = {0};

  const char clr[] = {27, '[', '2', 'J', '\0'};
  const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

  /* Clear screen and move to top left */
  // printf("%s%s", clr, topLeft);

  printf("\nPort statistics ====================================");

  for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
    /* skip disabled ports */
    if ((enabled_port_mask & (1 << portid)) == 0)
      continue;

    for (uint32_t q = 0; q < rx_queue; q++) {

      uint64_t diff_tx = port_stats[portid][q].tx - prev_tx[portid][q];
      uint64_t diff_rx = port_stats[portid][q].rx - prev_rx[portid][q];
      uint64_t diff_dropped =
          port_stats[portid][q].dropped - prev_dropped[portid][q];

      if (!(diff_tx == 0 && diff_rx == 0 && diff_dropped == 0)) {

        printf(
            "\nStatistics for port %u queue: %d ------------------------------"
            "\nPackets sent:     %'20llu (diff: %'llu)"
            "\nPackets received: %'20llu (diff: %'llu)"
            "\nPackets dropped:  %'20llu (diff: %'llu)\n",
            portid, q, (unsigned long long)port_stats[portid][q].tx,
            (unsigned long long)diff_tx,
            (unsigned long long)port_stats[portid][q].rx,
            (unsigned long long)diff_rx,
            (unsigned long long)port_stats[portid][q].dropped,
            (unsigned long long)diff_dropped);
      }

      total_packets_dropped += port_stats[portid][q].dropped;
      total_packets_tx += port_stats[portid][q].tx;
      total_packets_rx += port_stats[portid][q].rx;
      /* Update previous statistics */
      prev_tx[portid][q] = port_stats[portid][q].tx;
      prev_rx[portid][q] = port_stats[portid][q].rx;
      prev_dropped[portid][q] = port_stats[portid][q].dropped;
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
  //printf("total: %u\n", total);
  if (bypass)
    printf("With bypass\n");
  else
    printf("Without bypass\n");
  if (debug)
    printf("With debug\n");
  else
    printf("Without debug\n");
  if (debug_timestamp)
    printf("With debug timestamp\n");
  else
    printf("Without debug timestamp\n");
  if (retransmit)
    printf("With retransmission\n");
  else
    printf("Without retransmission\n");
  if (freerunning)
    printf("With freerunning cmpt overflow check\n");
  else
    printf("Without freerunning cmpt overflow check\n");
  if (elastic)
    printf("With elastic ring\n");
  else
    printf("Without elastic ring\n");

  if (rx_queue == 1) {
    printf("Completion errors: %lu (diff:%'ld)\n", cmpl_error,
           cmpl_error - prev_cmpl_error);
    printf("Seq Completion errors: %lu (diff:%'ld)\n", cmpl_error_seq,
           cmpl_error_seq - prev_cmpl_error_seq);
    printf("Dup Completion errors: %lu (diff:%'ld)\n", cmpl_error_dup,
           cmpl_error_dup - prev_cmpl_error_dup);
  }
  if (debug)
    printf("Debug errors: %lu (diff:%'ld)\n", debug_error,
           debug_error - prev_debug_error);

  prev_cmpl_error = cmpl_error;
  prev_cmpl_error_seq = cmpl_error_seq;
  prev_cmpl_error_dup = cmpl_error_dup;
  prev_debug_error = debug_error;
  /*if (rx_queue>1)
          for (int q=0; q<1; q++) {
                  printf("==========Q=%d=========\n",q);
                  print_c2h_ring_status((void*)dev->data->rx_queues[q],(void*)dev->data->tx_queues[q]);
          }
  */
  uint32_t full_counter = qdma_reg_read_usr(dev, 0x514C);

  printf("full_counter: %u\n", full_counter);
  //printf("full_counter+received: %'12lu\n", full_counter + measured_packets_rx);

  printf("\n====================================================\n");

  /*for (int q = 0; q < 2; q++) {
    uint32_t counter = get_bypass_pidx(dev, q) & 0x0ffff;
    uint32_t pidx = get_bypass_pidx(dev, q) % 1024;
    uint32_t cidx = get_bypass_cidx(dev, q);
    int32_t level = pidx - cidx;
    printf("BYPASS (%d) pidx: %u cidx: %u counter: %u", q, pidx, cidx, counter);
    if (pidx == cidx)
      printf("  (EMPTY) ");
    else if ((pidx + 1 == cidx) || (pidx == 1023 && cidx == 0))
      printf("  (FULL) ");
    else
      printf("  LEVEL: %d", level);
    printf("\n");
  }*/

  printf("\n====================================================\n");

  measured_tick++;
  uint32_t val_l = qdma_reg_read_usr(dev, 0xB020);
  uint32_t val_h = qdma_reg_read_usr(dev, 0xB024);
  uint64_t rx_pkt = ((uint64_t)val_h << 32) | val_l;
  printf("packets on q=0 : %'14lu\n", port_stats[0][0].rx);
  printf("packets on q=1 : %'14lu\n", port_stats[0][1].rx);
  printf("packets on q=2 : %'14lu\n", port_stats[0][2].rx);
  printf("packets on q=3 : %'14lu\n", port_stats[0][3].rx);

  printf("Packet Adapter received packets: %ld (diff: %'14ld)\n", rx_pkt,
         rx_pkt - rx_pkt_prev);
  rx_pkt_prev = rx_pkt;
  uint32_t rx_pkt2 =
      qdma_reg_read_usr(dev, 0x512C) - 1; // start from 1 to sync with CMPL id
  printf("QDMA Subsystem received packets: %d\n", rx_pkt2);
  printf("diff: %lu\n", rx_pkt - rx_pkt2);

  printf("prefetch distance: %u\n", prefetch_distance);
  printf("\n====================================================\n");

  /* Reset previous statistics */
  total_packets_tx_prev = total_packets_tx;
  total_packets_rx_prev = total_packets_rx;
  total_packets_dropped_prev = total_packets_dropped;

  if (rte_eth_stats_get(0, &stats) < 0) {
    printf("Error getting stats for port %u\n", 0);
  }
  fflush(stdout);
}

static void mac_updating(struct rte_mbuf *m, unsigned dest_portid) {
  /*struct rte_ether_hdr *eth;
  void *tmp;

  eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

  /* 02:00:00:00:00:xx */
  //tmp = &eth->d_addr.addr_bytes[0];
  //*((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dest_portid << 40);

  /* src addr */
  //rte_ether_addr_copy(&ports_eth_addr[dest_portid], &eth->s_addr);
  //
   struct rte_ether_hdr *eth;
   struct rte_ether_addr tmp;

   eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

   /* Save destination MAC */
   rte_ether_addr_copy(&eth->d_addr, &tmp);

   /* dst = src */
   rte_ether_addr_copy(&eth->s_addr, &eth->d_addr);

   /* src = fixed MAC */
   struct rte_ether_addr new_src = {
       .addr_bytes = {0x00, 0x0A, 0x35, 0xE8, 0x6F, 0x8E}
   };

   rte_ether_addr_copy(&new_src, &eth->s_addr);
}

static void cms_count_add(struct rte_mbuf *m) {
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

  uint64_t seed = 0x12345678; // fixed seed for reproducibility
  for (uint32_t i = 0; i < num_rand; i++) {
    seed += rte_rand();
  }
  for (uint32_t i = 0; i < num_hash; i++) {
    uint64_t h = xxhash64((const char *)&key, sizeof(key), seed + i);
    uint32_t target_idx = h & (cms_columns - 1);
    cm->values[i][target_idx]++;
  }
}

static void l2_forward(struct rte_mbuf *m, unsigned portid) {
  unsigned dst_port;

  dst_port = dst_ports[portid];

  if (mac_updating_flag)
    mac_updating(m, dst_port);
}

static void inline process_packet_maglev(struct rte_mbuf *m) {

  struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
  // Check if this is a IP packet
  if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
    printf("Not an IPv4 packet %x \n", eth->ether_type);
      return;
  }

  struct iphdr *ip = (struct iphdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr));
  int ip_header_len = ip->ihl * 4;
  struct udphdr *udp =
      (struct udphdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr) + ip_header_len);

  struct session_id sid = {0};
  sid.saddr = ip->saddr;
  sid.daddr = inet_addr("10.129.2.121");
  sid.proto = ip->protocol;
  sid.sport = udp->source;
  sid.dport = htons(80);

  /* Look for known sessions */
  struct replace_info *rep = hashmap_lookup_elem(&active_sessions, &sid);
  // Replace the destination IP and port with the backend's IP and port
  if (rep) {
    if (rep->dir == DIR_TO_BACKEND) {
      ip->daddr = rep->addr;
      udp->dest = rep->port;
      memcpy(eth->d_addr.addr_bytes, rep->mac_addr, sizeof(eth->d_addr));
    } else {
      ip->saddr = rep->addr;
      udp->source = rep->port;
      memcpy(eth->s_addr.addr_bytes, rep->mac_addr, sizeof(eth->s_addr));
    }
    //printf("Existing session found, applying stored mapping\n");
    return;
  }

  /* New session, apply load balancing logic */
  struct service_id srvid = {
      .vaddr = sid.daddr, .vport = sid.dport, .proto = ip->protocol};
  // Print key information for debugging
  char src_ip_str[INET_ADDRSTRLEN];
  char dst_ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &sid.saddr, src_ip_str, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &sid.daddr, dst_ip_str, INET_ADDRSTRLEN);
  //printf("New session: %s:%d -> %s:%d (proto: %d)\n", src_ip_str, ntohs(sid.sport), dst_ip_str, ntohs(sid.dport), sid.proto);
  struct service_info *srvinfo = hashmap_lookup_elem(&services, &srvid);
  if (!srvinfo) {
    printf("ERROR: missing service --> DROPPING\n");
    return;
  }
  //printf("Service found\n");

  struct backend_id bkdid = {
      .service = srvid,
      .index =
          ((struct maglev *)hashmap_lookup_elem(&maglev_tables, &srvid))
              ->bkd_mapping[murmurhash(&sid, sizeof(struct session_id), 0) %
                            MAGLEV_LOOKUP_SIZE]};
  struct backend_info *bkdinfo = hashmap_lookup_elem(&backends, &bkdid);

  if (!bkdinfo) {
    printf("ERROR: missing backend --> DROPPING\n");
    return;
  }

  /* Store the forward session */
  struct replace_info fwd_rep;
  fwd_rep.dir = DIR_TO_BACKEND;
  fwd_rep.addr = bkdinfo->addr;
  fwd_rep.port = bkdinfo->port;
  fwd_rep.bkdindex = bkdid.index;
  memcpy(fwd_rep.mac_addr, &bkdinfo->mac_addr, sizeof(fwd_rep.mac_addr));
  rep = &fwd_rep;
  if (hashmap_insert_elem(&active_sessions, &sid, &fwd_rep) != 1) {
    printf("ERROR: unable to add forward session to map\n");
    return;
  }

  /* Store the backward session */
  struct replace_info bwd_rep;
  bwd_rep.dir = DIR_TO_CLIENT;
  bwd_rep.addr = srvid.vaddr;
  bwd_rep.port = srvid.vport;
  memcpy(&bwd_rep.mac_addr, eth->s_addr.addr_bytes, sizeof(eth->s_addr));
  sid.daddr = sid.saddr;
  sid.dport = sid.sport;
  sid.saddr = bkdinfo->addr;
  sid.sport = bkdinfo->port;
  if (hashmap_insert_elem(&active_sessions, &sid, &bwd_rep) != 1) {
    printf("ERROR: unable to add backward session to map\n");
    return;
  }
}

const char *nat_ip = "203.0.113.5";
uint16_t nat_port = 12345;

static void inline process_nat(struct rte_mbuf *m) {
  // parse headers
  struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
  // Check if this is a IP packet
  if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
    //printf("Not an IPv4 packet %x \n", eth->ether_type);
      return;
  }
  struct iphdr *ip = (struct iphdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr));
  int ip_header_len = ip->ihl * 4;
  struct rte_udp_hdr *udp =
      (struct rte_udp_hdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr) +
                             ip_header_len);

  // Change IP and port (Assuming SNAT;)
  ip->saddr = inet_addr(nat_ip);
  udp->src_port = htons(nat_port);
}

static void inline process_ids(struct rte_mbuf *m) {

  unsigned char *pkt = rte_pktmbuf_mtod(m, unsigned char *);
  int length = rte_pktmbuf_pkt_len(m);
  for (int i = 0; i < length; i += 64) {
    if (pkt[i] == 'a')
      dummy_count++;
  }
}

static void inline process_decryption(struct rte_mbuf *m) {

  struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
  
  // Check if this is a IP packet
  if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
    //printf("Not an IPv4 packet %x \n", eth->ether_type);
      return;
  }
  //struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr*) (eth+1);
  struct iphdr *ip =
      (struct iphdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr));
  int ip_header_len = ip->ihl * 4;
  
  //printf("Decryption: ip_header_len=%d\n", ip_header_len);
  
  // Check if this is a TCP packet
  /*printf("----------------------------------------------------\n");
  for (size_t i = 0; i < 64; i++) {
    printf("%02X ", (unsigned char) *((char *)eth + i));
  }
  printf("\n");
  printf("----------------------------------------------------\n");
  */
  
  if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) ||
    ip->protocol != IPPROTO_TCP) {
    //printf("Not a TCP packet %x %x \n", ip->protocol, IPPROTO_TCP);
      return;
    }
  
  struct rte_tcp_hdr *tcp =
      (struct rte_tcp_hdr *)(((uint8_t *)eth) + sizeof(struct rte_ether_hdr) +
                             ip_header_len);
  unsigned char *payload = (unsigned char *)(tcp + 1);
  int ip_total_len = rte_cpu_to_be_16(ip->tot_len);
  int tcp_header_len = (tcp->data_off >> 4) * 4;
  int payload_len = ip_total_len - ip_header_len - tcp_header_len;
  for (int i = 0; i < payload_len; i++)
    payload[i] = payload[i] + decryption_key;
}

static void inline mica_table_init(void) {
  if (table != NULL)
    return;

  const size_t page_size = 1048576 * 2;
  const size_t num_numa_nodes = 8;
  size_t alloc_overhead = sizeof(struct mehcached_item);

  // Log/data-area bytes needed: mica_db_size items, each holding a
  // sizeof(size_t)-byte key + VALUE_SIZE-byte value (see the preload loop
  // below) plus the dynamic allocator's own per-item overhead
  // (MEHCAHCED_DYNAMIC_OVERHEAD, alloc_dynamic.h) -- same formula used for
  // the pool_size argument to mehcached_table_init() further down.
  size_t mica_log_item_size = alloc_overhead + sizeof(size_t) +
                              (size_t)VALUE_SIZE +
                              16 /* MEHCAHCED_DYNAMIC_OVERHEAD */;
  size_t mica_log_bytes = (size_t)(mica_db_size * mica_log_item_size * 1.10);

  // Bucket-area bytes needed: mehcached_table_init() rounds num_buckets up
  // to the next power of two and adds 10% extra_buckets on top (see
  // ported-mica/table.c) -- mirror that here so the shared-memory arena
  // below is actually sized to fit them. This used to be a FIXED 512 pages
  // (~896MB) regardless of --mica-db-size, which silently failed
  // mehcached_shm_alloc() ("insufficient memory on numa node...") for any
  // db size whose bucket+log data didn't fit (~4.25GB needed for 10000000
  // keys, for example). Worse, since -DNDEBUG turns the assert(false) that
  // used to catch that failure into a no-op, execution continued with an
  // invalid (SIZE_MAX) shm_id, straight into undefined behavior
  // (out-of-bounds mehcached_shm_entries[] access) -- surfacing as the
  // "invalid entry" prints from mehcached_shm_map()/schedule_remove().
  size_t mica_num_buckets = 1;
  while (mica_num_buckets < mica_db_size)
    mica_num_buckets <<= 1;
  size_t mica_bucket_bytes = (mica_num_buckets + mica_num_buckets / 10) *
                             sizeof(struct mehcached_bucket);

  // Total arena in 2MB pages, with the same 1/8 reserve-margin ratio the
  // original fixed sizing used, plus a small fixed safety pad, floored at
  // the original 512-page (~896MB) default so small/default --mica-db-size
  // values keep at least the same headroom as before.
  size_t mica_arena_pages =
      (mica_bucket_bytes + mica_log_bytes + page_size - 1) / page_size;
  mica_arena_pages += mica_arena_pages / 8 + 64;
  const size_t needed_pages = RTE_MAX((size_t)512, mica_arena_pages);

  // mehcached_shm_init() below splits num_pages_to_reserve *evenly across
  // all num_numa_nodes NUMA nodes* (see the per-node quota in
  // ported-mica/shm.c), but the bucket array and log/pool below are both
  // allocated on a single hardcoded NUMA node (table_numa_node=0 in the
  // mehcached_table_init() call further down). That means only 1/num_numa_nodes
  // of whatever we ask for here ever lands on the node we actually use --
  // silently capping real usable memory to ~needed_pages/num_numa_nodes
  // regardless of --mica-db-size. This is what let mica-db-size=100000
  // work (needed bytes happened to fit in that 1/num_numa_nodes share) while
  // mica-db-size=1000000 failed with "insufficient memory on numa node 0"
  // (swallowed by -DNDEBUG into the "invalid entry" prints from
  // mehcached_shm_map()/schedule_remove()). Inflate the request so node 0's
  // eventual 1/num_numa_nodes share is still >= needed_pages.
  const size_t umem_size = (needed_pages * num_numa_nodes * 8 + 6) / 7;
  const size_t num_pages_to_try = umem_size;
  const size_t num_pages_to_reserve = umem_size - umem_size / 8;

  // MEHCACHED_SHM_MAX_PAGES in ported-mica/shm.c -- mehcached_shm_init()
  // asserts num_pages_to_try against it; fail loudly here instead of
  // hitting that assert (a no-op under -DNDEBUG, which would silently
  // continue with an under-sized/uninitialized arena).
  const size_t mehcached_shm_max_pages = 65536;
  if (num_pages_to_try > mehcached_shm_max_pages)
    rte_exit(EXIT_FAILURE,
              "mica-db-size=%" PRIu64 " needs %zu 2MB pages, which exceeds "
              "MEHCACHED_SHM_MAX_PAGES (%zu); reduce --mica-db-size\n",
              mica_db_size, num_pages_to_try, mehcached_shm_max_pages);

  mehcached_shm_init(page_size, num_numa_nodes, num_pages_to_try,
                     num_pages_to_reserve);

  default_keys = malloc(mica_db_size * sizeof(size_t));
  if (default_keys == NULL)
    rte_exit(EXIT_FAILURE, "Cannot allocate default_keys (mica-db-size=%" PRIu64 ")\n",
              mica_db_size);

  table = &table_o;
  size_t numa_nodes[] = {(size_t)-1};
  // mehcached_table_init(table, 1, 1, 256, false, false, false,
  // numa_nodes[0], numa_nodes, MEHCACHED_MTH_THRESHOLD_FIFO);
  // Hardcoded 2 instead of numa_nodes[0]
  // MEHCACHED_NO_EVICTION means a bucket that fills up simply rejects new
  // inserts (mehcached_set() returns false) instead of evicting an older
  // item. Sizing buckets at ~1 bucket per key (num_buckets ~= mica_db_size,
  // i.e. average occupancy ~= 1 out of MEHCACHED_ITEMS_PER_BUCKET slots)
  // keeps the chance of any single bucket overflowing from real hash
  // collisions negligible, even across the tens of thousands of buckets a
  // large --mica-db-size produces. Sizing it at (mica_db_size /
  // MEHCACHED_ITEMS_PER_BUCKET), i.e. banking on a perfectly uniform hash
  // to fill every bucket to capacity, is not safe: at that load factor a
  // preload of 100000 sequential keys reliably overflows some bucket.
  // Log/data-area size: must fit mica_db_size items each holding a
  // sizeof(size_t)-byte key and a VALUE_SIZE-byte value -- that's exactly
  // what the preload loop below writes for every one of the mica_db_size
  // keys. The previous formula assumed an 8-byte value (mica_db_size *
  // (alloc_overhead + 8 + 8)), i.e. ~32x too small versus the real
  // VALUE_SIZE=256 preload payload: the log-structured allocator ran out
  // of space partway through preloading (observed: "bucket full" -- really
  // "log full", mehcached_set() returns false either way -- starting
  // around key ~mica_db_size * 0.14, consistent with that ~32x undersize)
  // and every subsequent key failed to preload. Runtime SET traffic from
  // process_mica_udp() writes smaller values (tiny/small, 8-32B) than this
  // 256B preload, so sizing for the preload gives it headroom too.
  //
  // Per-item bytes actually consumed in the log = sizeof(struct
  // mehcached_item) + the key/value themselves (already 8-byte aligned
  // here) + MEHCAHCED_DYNAMIC_OVERHEAD (alloc_dynamic.h: 16 bytes of
  // chunk header/footer the allocator adds on top of what we ask for).
  // Missing that 16-byte allocator overhead is exactly what left the
  // first fixed formula ~3.5% short (e.g. 100000 keys -> failures
  // starting around key ~96580 instead of all 100000 succeeding). A
  // further 10% fudge factor covers the allocator's free-list size-class
  // rounding, which isn't accounted for at all above. (mica_log_item_size
  // / mica_log_bytes are computed above, before mehcached_shm_init(), so
  // the arena can be sized to fit this same pool_size.)
  mehcached_table_init(
      table, mica_db_size,
      1, mica_log_bytes, false,
      false, false, 0, numa_nodes, MEHCACHED_MTH_THRESHOLD_FIFO);
  assert(table);

  char default_value[VALUE_SIZE];
  memset(default_value, 'A', VALUE_SIZE - 1);
  default_value[VALUE_SIZE - 1] = '\0';

  for (size_t i = 0; i < mica_db_size; i++) {
    size_t key = i;
    default_keys[i] = key;

    uint64_t key_hash = hash((const uint8_t *)&key, sizeof(key));
    if (!mehcached_set(0, table, key_hash, (const uint8_t *)&key, sizeof(key),
                       (const uint8_t *)&default_value, sizeof(default_value),
                       0, false))
      fprintf(stderr, "mica_table_init: failed to preload key %zu (bucket full)\n", key);
  }
}

static void inline process_mica(struct rte_mbuf *m) {
  mica_table_init();
  struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
  if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
    //printf("Not an IPv4 packet %x \n", eth->ether_type);
      return;
  }
  struct iphdr *ip =
      (struct iphdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr));
  int ip_header_len = ip->ihl * 4;
  struct rte_tcp_hdr *tcp=
      (struct rte_tcp_hdr *)(((uint8_t *)eth) + sizeof(struct rte_ether_hdr) +
                             ip_header_len);

  size_t key;
  char value[VALUE_SIZE];

  // get key
  memcpy(&key, tcp, sizeof(size_t));
  flag = !flag;
  key = default_keys[keys_index];
  keys_index = (keys_index + 1) % mica_db_size;

  // GET
  if (flag) {
    uint64_t key_hash = hash((const uint8_t *)&key, sizeof(key));
    size_t value_length = sizeof(value);

    if (mehcached_get(0, table, key_hash, (const uint8_t *)&key, sizeof(key),
                      (uint8_t *)&value, &value_length, NULL, false))
      assert(value_length == sizeof(value));

    // send value
    memcpy((unsigned char *)(tcp + 1) + sizeof(size_t), &value, VALUE_SIZE);
  }

  // STORE
  else {
    memcpy(value, (unsigned char *)(tcp + 1) + sizeof(size_t), VALUE_SIZE);
    value[VALUE_SIZE - 1] = '\0';
    uint64_t key_hash = hash((const uint8_t *)&key, sizeof(key));
    if (!mehcached_set(0, table, key_hash, (const uint8_t *)&key, sizeof(key),
                       (const uint8_t *)&value, sizeof(value), 0, true))
      fprintf(stderr, "process_mica: SET failed for key %zu (bucket full)\n", key);

    // send acknowledgement
    memcpy((unsigned char *)(tcp + 1) + sizeof(size_t), &value, VALUE_SIZE);
  }
}

// Second MICA application: unlike process_mica() above (which alternates
// GET/SET internally and ignores the packet contents), this one is driven
// by the packet itself. Two independent GET/SET opcode pairs are supported,
// one per key/value size class:
//
//   "tiny"  : 8-byte key,  8-byte value  -> MICA_UDP_OP_GET_TINY / MICA_UDP_OP_SET_TINY
//   "small" : 16-byte key, 32-byte value -> MICA_UDP_OP_GET_SMALL / MICA_UDP_OP_SET_SMALL
//
// Since the key/value sizes are fixed by the opcode, no length fields are
// carried on the wire. UDP payload layout:
//
//   byte 0                : opcode (one of the 4 above)
//   bytes 1..KEY_SIZE     : key
//   bytes ..+VALUE_SIZE   : value (SET only)
//
// For a GET request the looked-up value is written back in place right
// after the key; for a SET request the stored value is echoed back as an
// acknowledgement, exactly like process_mica() does.
static void inline process_mica_udp(struct rte_mbuf *m) {
  mica_table_init();

  struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
  if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
    //printf("Not an IPv4 packet %x \n", eth->ether_type);
    return;
  }
  struct iphdr *ip =
      (struct iphdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr));
  if (ip->protocol != IPPROTO_UDP) {
    //printf("Not a UDP packet %x \n", ip->protocol);
    return;
  }
  int ip_header_len = ip->ihl * 4;
  struct rte_udp_hdr *udp =
      (struct rte_udp_hdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr) +
                             ip_header_len);
  unsigned char *payload = (unsigned char *)(udp + 1);

  uint8_t opcode = payload[0];
  unsigned char *key_ptr = payload + 1;

  switch (opcode) {
  case MICA_UDP_OP_GET_TINY: {
    size_t key = 0;
    memcpy(&key, key_ptr, TINY_KEY_SIZE);
    uint64_t key_hash = hash((const uint8_t *)&key, TINY_KEY_SIZE);

    char value_tiny[TINY_VALUE_SIZE];
    size_t value_length = sizeof(value_tiny);
    if (mehcached_get(0, table, key_hash, (const uint8_t *)&key,
                      TINY_KEY_SIZE, (uint8_t *)&value_tiny, &value_length,
                      NULL, false))
      assert(value_length == sizeof(value_tiny));

    // send value back right after the key
    //printf("GET TINY: key %zu, value %.*s\n",key,TINY_VALUE_SIZE,value_tiny);
    memcpy(key_ptr + TINY_KEY_SIZE, value_tiny, TINY_VALUE_SIZE);
    break;
  }
  case MICA_UDP_OP_SET_TINY: {
    size_t key = 0;
    memcpy(&key, key_ptr, TINY_KEY_SIZE);
    uint64_t key_hash = hash((const uint8_t *)&key, TINY_KEY_SIZE);

    unsigned char *val_ptr = key_ptr + TINY_KEY_SIZE;
    char value_tiny[TINY_VALUE_SIZE];
    memcpy(value_tiny, val_ptr, TINY_VALUE_SIZE);

    // A failed insert (bucket full -- see mica_table_init()) just means
    // this SET didn't take; still ack with the value the client sent so
    // one bad request doesn't take down the whole server (no assert here,
    // this runs per-packet).
    mehcached_set(0, table, key_hash, (const uint8_t *)&key,
                 TINY_KEY_SIZE, (const uint8_t *)&value_tiny,
                 TINY_VALUE_SIZE, 0, true);

    // send acknowledgement
    //printf("SET TINY: key %zu, value %.*s\n",key,(int)TINY_VALUE_SIZE,value_tiny);
    memcpy(val_ptr, value_tiny, TINY_VALUE_SIZE);
    break;
  }
  case MICA_UDP_OP_GET_SMALL: {
    unsigned char key_small[SMALL_KEY_SIZE];
    memcpy(key_small, key_ptr, SMALL_KEY_SIZE);
    uint64_t key_hash = hash((const uint8_t *)key_small, SMALL_KEY_SIZE);

    char value_small[SMALL_VALUE_SIZE];
    size_t value_length = sizeof(value_small);
    if (mehcached_get(0, table, key_hash, (const uint8_t *)key_small,
                      SMALL_KEY_SIZE, (uint8_t *)&value_small, &value_length,
                      NULL, false))
      assert(value_length == sizeof(value_small));

    // send value back right after the key
    //printf("GET SMALL: key %.*s, value %.*s\n",SMALL_KEY_SIZE,key_small,SMALL_VALUE_SIZE,value_small);
    memcpy(key_ptr + SMALL_KEY_SIZE, value_small, SMALL_VALUE_SIZE);
    break;
  }
  case MICA_UDP_OP_SET_SMALL: {
    unsigned char key_small[SMALL_KEY_SIZE];
    memcpy(key_small, key_ptr, SMALL_KEY_SIZE);
    uint64_t key_hash = hash((const uint8_t *)key_small, SMALL_KEY_SIZE);

    unsigned char *val_ptr = key_ptr + SMALL_KEY_SIZE;
    char value_small[SMALL_VALUE_SIZE];
    memcpy(value_small, val_ptr, SMALL_VALUE_SIZE);

    // See MICA_UDP_OP_SET_TINY above: don't crash the server on a failed
    // insert, just ack with whatever the client sent.
    mehcached_set(0, table, key_hash, (const uint8_t *)key_small,
                 SMALL_KEY_SIZE, (const uint8_t *)&value_small,
                 SMALL_VALUE_SIZE, 0, true);

    // send acknowledgement
    //printf("SET SMALL: key %.*s, value %.*s\n",SMALL_KEY_SIZE,key_small,SMALL_VALUE_SIZE,value_small);
    memcpy(val_ptr, value_small, SMALL_VALUE_SIZE);
    break;
  }
  default:
    //printf("Unknown MICA opcode %u\n", opcode);
    break;
  }
}

// R2P2 (application ids 10=R2P2_ECHO, 11=R2P2_STSS): parses Eth/IPv4/UDP
// exactly like cms_count_add()/process_mica_udp() above, then hands the
// UDP payload to r2p2's own protocol core (r2p2/r2p2/r2p2-common.c,
// vendored unmodified) via handle_incoming_pck(). That core takes care of
// request reassembly/ACKs and, once a full request is in, calls whichever
// recv callback main() registered for the selected application
// (r2p2_glue_echo_recv() or r2p2_glue_stss_recv() -- see r2p2_glue.{h,c}).
// Both applications share this same parsing function: the only
// difference between them is which callback was registered.
static void inline process_r2p2(struct rte_mbuf *m) {
  struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
  if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
    return;

  struct iphdr *ip = (struct iphdr *)(eth + 1);
  if (ip->protocol != IPPROTO_UDP)
    return;

  int ip_header_len = ip->ihl * 4;
  struct rte_udp_hdr *udp =
      (struct rte_udp_hdr *)((uint8_t *)ip + ip_header_len);
  if (udp->dst_port != r2p2_local_port_be)
    return;

  int udp_len = rte_be_to_cpu_16(udp->dgram_len);
  if (udp_len < (int)sizeof(struct rte_udp_hdr))
    return;

  r2p2_glue_prep_rx(m, sizeof(struct rte_ether_hdr), ip_header_len,
                    sizeof(struct rte_udp_hdr));
  r2p2_glue_on_request(r2p2_tx_portid, r2p2_tx_queue, pktmbuf_pool[r2p2_tx_queue],
                       ip->saddr, &eth->s_addr);

  struct r2p2_host_tuple source = {.ip = ip->saddr, .port = udp->src_port};
  struct r2p2_host_tuple local = {.ip = r2p2_local_ip_be,
                                  .port = r2p2_local_port_be};

  handle_incoming_pck((generic_buffer)m, udp_len - sizeof(struct rte_udp_hdr),
                      &source, &local);
}

static void inline process_nitrosketch(struct rte_mbuf *m) {
  // NitroSketch: DS init
  static uint64_t pkt_count = 0;

// #define NITRO_CS 1
#ifdef NITRO_CMS
  if (nitro_cm == NULL) {
    nitro_cm = (CountMinSketch *)malloc(sizeof(CountMinSketch));
    cm_init(nitro_cm, CM_COL_NO, 0.01);
  }
#endif
#ifdef NITRO_CS
  if (nitro_cs == NULL) {
    nitro_cs = (CountSketch *)malloc(sizeof(CountSketch));
    cs_init(nitro_cs, CS_COL_NO, 0.01);
  }
#endif

  /* Run until the application is quit or killed. */

  pkt_count++;
  struct rte_ether_hdr *eth_hdr = (rte_pktmbuf_mtod(m, struct rte_ether_hdr *));

  if (likely(eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))) {

#ifdef NITRO_CMS
    while (pkt_count >= nitro_cm->nextUpdate) {
#endif
#ifdef NITRO_CS
      while (pkt_count >= nitro_cs->nextUpdate) {
#endif
        struct rte_ipv4_hdr *ip_hdr = ((struct rte_ipv4_hdr *)(eth_hdr + 1));

        uint64_t flow_key =
            (ip_hdr->src_addr | (((uint64_t)ip_hdr->dst_addr) << 32));
#ifdef NITRO_CMS
        cm_processing(nitro_cm, flow_key);
#endif

#ifdef NITRO_CS
        cs_processing_always_line_rate(nitro_cs, flow_key);
#endif
      }
    }
    // Swap MAC
    struct rte_ether_addr temp_mac_addr = eth_hdr->s_addr;
    eth_hdr->s_addr = eth_hdr->d_addr;
    eth_hdr->d_addr = temp_mac_addr;
  }

  static void inline process_packet(struct rte_mbuf * m) {
    switch (application) {
    case RX_COUNT: // RX count
      break;
    case L2_FWD: // L2 forward
      l2_forward(m, 0);
      break;
    case COUNT_MIN_SKETCH: // count min sketch + Workpackage
      cms_count_add(m);
      break;
    case MAGLEV: // maglev load balancer
      process_packet_maglev(m);
      break;
    case NAT: // nat
      process_nat(m);
      break;
    case IDS:
      process_ids(m);
      break;
    case DECRYPTION:
      process_decryption(m);
      break;
    case MICA:
      process_mica(m);
      break;
    case NITROSKETCH:
      process_nitrosketch(m);
      break;
    case MICA_UDP:
      process_mica_udp(m);
      break;
    case R2P2_ECHO:
    case R2P2_STSS:
      process_r2p2(m);
      break;
    default:
      l2_forward(m, 0);
      break;
    }
  }

  /* main processing loop */
  static void main_loop(void) {
    uint64_t measured_packets_rx = 0;
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
      RTE_LOG(INFO, DOL, "lcore %u has nothing to do\n", lcore_id);
      return;
    }

    RTE_LOG(INFO, DOL, "entering main loop on lcore %u\n", lcore_id);

    for (i = 0; i < qconf->n_rx_port; i++) {

      portid = qconf->rx_port_list[i];
      RTE_LOG(INFO, DOL, " -- lcoreid=%u portid=%u\n", lcore_id, portid);
      RTE_LOG(INFO, DOL, " -- lcoreid=%u portid=%u\n", lcore_id, portid);
    }

    uint16_t pktid_prev = 255;

    // r2p2's client_pairs/server_pairs pools are __thread (per-lcore); must
    // be allocated once on every lcore that will run process_r2p2().
    if (application == R2P2_ECHO || application == R2P2_STSS)
      r2p2_glue_init_per_core();

    while (!force_quit) {
      // if (total >300) {
      //   print_stats();
      //   break;
      // }
      cur_tsc = rte_rdtsc();

      /*
       * TX burst queue drain
       */
      diff_tsc = cur_tsc - prev_tsc;
      if (unlikely(diff_tsc > drain_tsc)) {

        for (i = 0; i < qconf->n_rx_port; i++) {

          portid = dst_ports[qconf->rx_port_list[i]];
          buffer = tx_buffer[portid];
          sent = rte_eth_tx_buffer_flush(portid, 0, buffer);
          if (sent)
            port_stats[portid][0].tx += sent;
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
      for (i = 0; i < qconf->n_rx_port; i++) {
        portid = qconf->rx_port_list[i];
        //for (uint32_t q = 0; q < rx_queue; q++) {
        for (int ii = 0; ii< rx_queue_per_core; ii++){
          //{
          uint32_t q = rx_queue_per_core*qconf->id+ii; 

          nb_rx = rte_eth_rx_burst(portid, q, pkts_burst, MAX_PKT_BURST);

          port_stats[portid][q].rx += nb_rx;

          for (j = 0; j < nb_rx; j++) {
            m = pkts_burst[j];
            uint16_t pkid = m->timesync; // using timesync field to store packet
                                         // ID for simplicity: global (not per
                                         // queue) packet counter
            /*
            if ((sw_pkt_id != pkid) && (rx_queue == 1)) {
              /*
              printf("----------------------------------------------------\n");
              printf("---               Completion error               ---\n");
              printf("total: %u\n", total);
              printf("Packet ID mismatch! Expected: %u, Actual: %u diff:%d\n",
              sw_pkt_id, pkid,pkid-sw_pkt_id); printf("pktid: %d\n", pkid);
              printf("pktid_prev: %d\n", pktid_prev);
              printf("completion error: %lu\n",cmpl_error);
              printf("----------------------------------------------------\n");
              /
              cmpl_error++;
              sw_pkt_id =
                  pkid; // resync software packet ID to avoid cascading errors
            }*/
            /*if (pkid == pktid_prev)
              cmpl_error_dup++;
            if (pkid != (pktid_prev + 1) && (pkid != 0) &&
                (pkid != pktid_prev)) {
              cmpl_error_seq++;
              /*
              printf("lost completion entry\n");
              printf("pktid: %d\n", pkid);
              printf("pktid_prev: %d\n", pktid_prev);
            }*/

            if (debug) {
              /*
              printf("Debug: Queue ID: %d   CMPL ID: %d\n", q,pkid);
              printf("Phys_addr: %p\n", (void*)rte_pktmbuf_mtod(m, void *));
              int64_t payload_id= *(uint32_t*)((uint8_t*)rte_pktmbuf_mtod(m,
              void *)+31); printf("Payload id: %ld\n", payload_id);


              uint8_t* pkt_data = (uint8_t*)rte_pktmbuf_mtod(m, uint8_t *);
              printf("----------------------------------------------------\n");
              for (size_t i = 0; i < 64; i++) {
                                        printf("%02X ", *(pkt_data + i));
                                      }
                                      printf("\n");
              printf("----------------------------------------------------\n");
              */
              uint32_t pkt_len = rte_pktmbuf_pkt_len(m);
              // int64_t payload_id= *(uint32_t*)((uint8_t*)rte_pktmbuf_mtod(m,
              // void *)+31);
              /*
              uint32_t tx_timestamp =
                  *(uint32_t *)((uint8_t *)rte_pktmbuf_mtod(m, void *) + 43);
              uint32_t rx_timestamp =
                  *(uint32_t *)((uint8_t *)rte_pktmbuf_mtod(m, void *) + 39);
              printf("RX timestamp: %u, TX timestamp: %u\n", rx_timestamp,
              tx_timestamp);
                  //uint32_t latency = tx_timestamp - rx_timestamp;
              */
              uint32_t payload_counter =
                  *(uint32_t *)((uint8_t *)rte_pktmbuf_mtod(m, void *) + 35);
              uint16_t qid =
                  *(uint16_t *)((uint8_t *)rte_pktmbuf_mtod(m, void *) + 26);
              if (qid != q) {
                printf(
                    "----------------------------------------------------\n");
                printf("Debug: Queue ID mismatch! Expected: %d, Actual: %d\n",
                       q, qid);
                printf(
                    "----------------------------------------------------\n");

                printf(
                    "----------------------------------------------------\n");
                printf(
                    "----------------------------------------------------\n");
                printf("Q0 packet data:\n");
                for (int k = 0; k < 1024; k++) {
                  printf("packet %d:\n", k);
                  for (size_t i = 0; i < 32; i++) {
                    printf("%X ",
                           *(((uint8_t *)q0_phys_addr_start) + k * 2368 + i));
                  }
                  printf("\n");
                }
                printf("Q1 packet data:\n");
                for (int k = 0; k < 1024; k++) {
                  printf("packet %d:\n", k);
                  for (size_t i = 0; i < 32; i++) {
                    printf("%X ",
                           *(((uint8_t *)q1_phys_addr_start) + k * 2368 + i));
                  }
                  printf("\n");
                }
              }
              if (pkt_len > 64) {
                // payload_id= *(uint32_t*)((uint8_t*)rte_pktmbuf_mtod(m, void
                // *)+95);
                payload_counter =
                    *(uint32_t *)((uint8_t *)rte_pktmbuf_mtod(m, void *) + 99);
              }
              if ((pkid + cmpl_error & 0x0FFFF) !=
                  (payload_counter & 0x0FFFF)) {
                printf("Debug: Packet ID mismatch between CMPL id and payload "
                       "counter: payload_id: %u pkid:%d,  diff: %u\n",
                       payload_counter & 0x0FFFF, pkid,
                       (payload_counter & 0x0FFFF) - pkid);
                printf("debug error: %lu\n", debug_error);
                printf("completion error: %lu\n", cmpl_error);
                printf("pktid: %d\n", pkid);
                printf("pktid_prev: %d\n", pktid_prev);
                printf(
                    "----------------------------------------------------\n");
              }

              int64_t debug_addr =
                  *(int64_t *)((uint8_t *)rte_pktmbuf_mtod(m, void *) + 14);
              /*
              char flag= *(char*)((uint8_t*)rte_pktmbuf_mtod(m, void *)+30);
              char tag= *(char*)((uint8_t*)rte_pktmbuf_mtod(m, void *)+28);
                                            printf("----------------------------------------------------\n");
                                            printf("From queue: %d \n", q);
              printf("Payload addr: %p --", (void*)debug_addr);
                                            printf("pkt_cnt=%u Packet ID:
              %ld\n", total, payload_id); printf("tag=%d qid: %d\n", tag, qid);
                                            printf("flag=0x%02x \n", flag);
                                            printf("----------------------------------------------------\n");
              */
              if (debug_addr != (int64_t)rte_pktmbuf_mtod(m, void *)) {
                printf(
                    "----------------------------------------------------\n");
                printf("Packet ID: %d\n", payload_counter);
                printf("Debug: Packet data address mismatch! Expected "
                       "(phys_addr): %p, Actual (from payload): %p --",
                       (void *)rte_pktmbuf_mtod(m, void *), (void *)debug_addr);
                printf("Diff %ld (%ld)\n",
                       debug_addr - (int64_t)rte_pktmbuf_mtod(m, void *),
                       abs(debug_addr - (int64_t)rte_pktmbuf_mtod(m, void *)) /
                           2368);
                printf(
                    "----------------------------------------------------\n");
              }
            }
            pktid_prev = pkid;
            //sw_debug_id[q]++;
            //sw_pkt_id++;

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
              uint8_t *pkt_data = (uint8_t *)rte_pktmbuf_mtod(m, uint8_t *);
              // printf("Packet data address (%ld): %p --", total,pkt_data);
              uint32_t pkt_len = rte_pktmbuf_pkt_len(m);
              // printf("Packet data:
              // %c%c%c%c\n",pkt_data[pkt_len-4],pkt_data[pkt_len-3],pkt_data[pkt_len-2],pkt_data[pkt_len-1]);
              pcap_write_packet(pkt_data, pkt_len);
            }

            // R2P2 replies are sent on their own (buf_list_send(), see
            // r2p2_glue.c), independently of this loop's bypass/retransmit
            // handling below -- it needs to know which port/queue to send
            // on, which process_packet(m)'s single-mbuf signature doesn't
            // carry. Harmless to set for every other application too.
            r2p2_tx_portid = (uint16_t)portid;
            r2p2_tx_queue = (uint16_t)q;
            process_packet(m);

            if ((!bypass) && (!retransmit)) {
              rte_pktmbuf_free(m);
            }
            measured_packets_rx++;
          }
          // TX burst
          if ((retransmit) && (nb_rx > 0)) {
            if (bypass)
              port_stats[0][q].tx += qdma_xmit_pkts_bypass(
                  dev->data->tx_queues[q], pkts_burst, nb_rx);
            else
              port_stats[0][q].tx +=
                  qdma_xmit_pkts(dev->data->tx_queues[q], pkts_burst, nb_rx);
          }

          // rearm!
          if (bypass && (nb_rx > 0)) {
          //if (bypass) {
            uint16_t cidx;
            if (!retransmit)
              cidx = get_cidx(dev->data->rx_queues[q]);
            else
              cidx = get_cidx_tx(dev->data->tx_queues[q],
                                 elastic); // read updated cidx from TX queue
            //if (rte_spinlock_trylock(&lock)) {
              update_direct2_cidx(
              //update_direct_cidx(
              //update_cidx(
                  dev, q, cidx,
                  prefetch_tag[q & qmask]); // update cidx to rearm the ring
              //rte_spinlock_unlock(&lock);
            //}
          }
        }
      }
    }
    if (application == NITROSKETCH) {
#ifdef NITRO_CMS
      print_sketch(nitro_cm, "output_dpdk_nitrosketch.txt");
#endif
#ifdef NITRO_CS
      print_sketch(nitro_cs, "output_dpdk_nitrosketch.txt");
#endif
    }
  }

  static int launch_one_lcore(void *arg) {
    main_loop();
    return 0;
  }

  /* display usage */
  static void usage(const char *prgname) {
    printf(
        "%s [EAL options] -- -p PORTMASK [-q NQ]\n"
        "  -d N: number of descriptors > 32 (default is 1024)\n"
        "  -p N: prefetch distance\n"
        "  -c N: configure number of columns (default is 1048576)\n"
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
        "	      Default: alternate port pairs\n"
        "  --mica-db-size N: number of distinct keys preloaded into the MICA "
        "table (default 2000, must match the traffic generator's "
        "--mica-db-size)\n\n",
        prgname);
  }

  static int parse_portmask(const char *portmask) {
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
      return 0;

    return pm;
  }

  static int parse_port_pair_config(const char *q_arg) {
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

  static unsigned int parse_n(const char *arg) {
    char *end = NULL;
    unsigned long n;

    /* parse hexadecimal string */
    n = strtoul(arg, &end, 10);
    if ((arg[0] == '\0') || (end == NULL) || (*end != '\0'))
      return 0;
    if (n == 0)
      return 0;

    return n;
  }

  static const char short_options[] = "c:" /* CMS columns  */
                                      "k:" /* number of hash functions */
                                      "r:" /* number of rand calls */
                                      "Q"  /* silent */
                                      "D"  /* dump pcap */
                                      "B"  /* enable bypass */
                                      "x"  /* enable debug */
                                      "X"  /* enable debug timestamp */
                                      "T"  /* enable retransmit */
                                      "F"  /* enable freerunning */
                                      "E"  /* enable elastic buffer */
                                      "P:" /* portmask */
                                      "q:" /* number of queues */
                                      "p:" /* prefetch distance */
                                      "d:" /* number of descriptors */
                                      "a:" /* application */
                                      "L"  /* enable LIFO */
                                      "t"  /* enable toasty logic */
                                      "s"  /* enable shRing logic */
      ;

  enum {
    /* long options mapped to a short option */

    /* first long only option value must be >= 256, so that we won't
     * conflict with short options */
    CMD_LINE_OPT_MIN_NUM = 256,
    CMD_LINE_OPT_PORTMAP_NUM,
    CMD_LINE_OPT_MICA_DB_SIZE_NUM,
    CMD_LINE_OPT_R2P2_IP_NUM,
    CMD_LINE_OPT_R2P2_PORT_NUM,
  };

  static const struct option lgopts[] = {
      {CMD_LINE_OPT_MAC_UPDATING, no_argument, &mac_updating_flag, 1},
      {CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, &mac_updating_flag, 0},
      {CMD_LINE_OPT_PORTMAP_CONFIG, 1, 0, CMD_LINE_OPT_PORTMAP_NUM},
      {CMD_LINE_OPT_MICA_DB_SIZE, required_argument, 0, CMD_LINE_OPT_MICA_DB_SIZE_NUM},
      {CMD_LINE_OPT_R2P2_IP, required_argument, 0, CMD_LINE_OPT_R2P2_IP_NUM},
      {CMD_LINE_OPT_R2P2_PORT, required_argument, 0, CMD_LINE_OPT_R2P2_PORT_NUM},
      {NULL, 0, 0, 0}};

  /* Parse the argument given in the command line of the application */
  static int parse_args(int argc, char **argv) {
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
      case 'a':
        application = parse_n(optarg);
        /* check application type*/
        if (application < 0 || application > 11) {
          printf("invalid application type\n");
          usage(prgname);
          return -1;
        }
        break;
      case 'c':
        cms_columns = parse_n(optarg);
        /* check that cms_columns is a power of 2 */
        if (cms_columns == 0 || (cms_columns & (cms_columns - 1)) != 0) {
          printf("invalid number of columns\n");
          usage(prgname);
          return -1;
        }
        break;
      case 'k':
        num_hash = parse_n(optarg);
        /* check that cms_columns is a power of 2 */
        if (num_hash < 0) {
          printf("invalid number of hash functions\n");
          usage(prgname);
          return -1;
        }
        break;
      case 'r':
        num_rand = parse_n(optarg);
        /* check that cms_columns is a power of 2 */
        if (num_rand < 0) {
          printf("invalid number of rand calls\n");
          usage(prgname);
          return -1;
        }
        break;
      case 'd':
        nb_rxd = parse_n(optarg);
        /* check that descriptors is a power of 2 */
        if (nb_rxd < 32 || (nb_rxd & (nb_rxd - 1)) != 0) {
          printf("invalid number of descriptors\n");
          usage(prgname);
          return -1;
        }
        break;
      case 'p':
        prefetch_distance = atoi(optarg);
        break;
      /* portmask */
      case 'P':
        enabled_port_mask = parse_portmask(optarg);
        if (enabled_port_mask == 0) {
          printf("invalid portmask\n");
          usage(prgname);
          return -1;
        }
        break;

      /* nqueue */
      case 'q':
        rx_queue = parse_n(optarg);
        if (rx_queue == 0) {
          printf("invalid queue number\n");
          usage(prgname);
          return -1;
        }
        break;
      case 'Q':
        silent = true;
        break;
      case 'D':
        dump = true;
        break;
      case 'L':
        lifo = true;
        break;
      case 'B':
        bypass = true;
        break;
      case 'x':
        debug = true;
        break;
      case 'X':
        debug_timestamp = true;
        break;
      case 'T':
        retransmit = true;
        break;
      case 'E':
        elastic = true;
        break;
      case 'F':
        freerunning = 1;
        break;
      case 't':
        toasty = true;
        break;
      case 's':
        shring = true;
        break;
      /* long options */
      case CMD_LINE_OPT_PORTMAP_NUM:
        ret = parse_port_pair_config(optarg);
        if (ret) {
          fprintf(stderr, "Invalid config\n");
          usage(prgname);
          return -1;
        }
        break;
      case CMD_LINE_OPT_MICA_DB_SIZE_NUM: {
        char *end = NULL;
        unsigned long long v = strtoull(optarg, &end, 10);
        if (optarg[0] == '\0' || end == NULL || *end != '\0' || v < 2) {
          fprintf(stderr, "invalid --mica-db-size '%s' (expected >= 2)\n", optarg);
          usage(prgname);
          return -1;
        }
        mica_db_size = (uint64_t)v;
        break;
      }
      case CMD_LINE_OPT_R2P2_IP_NUM: {
        struct in_addr addr;
        if (inet_aton(optarg, &addr) == 0) {
          fprintf(stderr, "invalid --r2p2-ip '%s'\n", optarg);
          usage(prgname);
          return -1;
        }
        r2p2_local_ip_be = addr.s_addr;
        break;
      }
      case CMD_LINE_OPT_R2P2_PORT_NUM: {
        char *end = NULL;
        unsigned long v = strtoul(optarg, &end, 10);
        if (optarg[0] == '\0' || end == NULL || *end != '\0' || v == 0 || v > 65535) {
          fprintf(stderr, "invalid --r2p2-port '%s' (expected 1-65535)\n", optarg);
          usage(prgname);
          return -1;
        }
        r2p2_local_port_be = rte_cpu_to_be_16((uint16_t)v);
        break;
      }

      default:
        usage(prgname);
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
        if ((enabled_port_mask & (1 << portid)) == 0) {
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

    enabled_port_mask &= port_pair_config_mask;

    return 0;
  }

  /* Check the link status of all ports in up to 9s, and print them finally */
  static void check_all_ports_link_status(uint32_t port_mask) {
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
          rte_eth_link_to_str(link_status_text, sizeof(link_status_text),
                              &link);
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
      /*for (uint32_t qid = 0; qid < rx_queue; qid++) {
          uint64_t r_addr;
          uint32_t r_tag;
          uint8_t r_valid;
          uint32_t r_num_desc;
          qdma_read_queue_bypass_registers(dev, qid, &r_addr, &r_tag, &r_valid,
        &r_num_desc); printf("q=%d addr: %lx tag:%u valid:%u
        desc:%u\n",qid,r_addr,r_tag,r_valid,r_num_desc);
        }*/

      force_quit = true;
    }
    if (signum == SIGQUIT) {
      // qdma_inv_rx_queue_ctxts(dev,0,1);
      // qdma_clr_rx_queue_ctxts(dev,0,1);
      /*uint16_t rx_cmpt_tail= get_cidx(dev->data->rx_queues[0]);
      printf("Current RX completion tail: %u\n", rx_cmpt_tail);
      int32_t val= qdma_reg_read(dev,0x1800C);
            val &= 0xffff0000;
            val += rx_cmpt_tail;
            qdma_reg_write(dev,0x1800C,val);
            rte_wmb();
            val= qdma_reg_read(dev,0x1800C);
      printf("cidx: %d\n",val &0x0ffff);*/
      for (uint32_t q = 0; q < rx_queue; q++) {

        uint16_t cidx;
        if (!retransmit)
          cidx = get_cidx(dev->data->rx_queues[q]);
        else
          cidx = get_cidx_tx(dev->data->tx_queues[q],
                             elastic); // read updated cidx from TX queue
        update_direct2_cidx(dev, q, cidx,
        //update_direct_cidx(dev, q, cidx,
        //update_cidx(dev, q, cidx,
                    prefetch_tag[q]); // update cidx to rearm the ring
      }
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
    // A terminal disconnect (SSH drop, closed session) sends SIGHUP with
    // no handler installed by default -- the process dies instantly with
    // zero cleanup (no bypass-register disarm, no dev_close). Treat it
    // the same as SIGINT/SIGTERM.
    signal(SIGHUP, signal_handler);

    rte_srand((unsigned)time(NULL));

    /* initialize hashmaps for maglev load balancer */
    hashmap_init(&services, sizeof(struct service_id), sizeof(struct service_info), MAX_SERVICES);
    hashmap_init(&backends, sizeof(struct backend_id), sizeof(struct backend_info), MAX_BACKENDS);
    hashmap_init(&maglev_tables, sizeof(struct service_id), sizeof(struct maglev), MAX_SERVICES);
    hashmap_init(&active_sessions, sizeof(struct session_id), sizeof(struct replace_info), MAX_SESSIONS);

    /* Populate services hashmap with a dummy entry */
    struct service_id dummy_service_id = {0};
    struct service_info dummy_service_info = {0};
    dummy_service_id.proto = IPPROTO_UDP; // UDP (17), not 0
    dummy_service_id.vaddr = inet_addr("10.129.2.121");
    dummy_service_id.vport = htons(80);
    dummy_service_info.backends = 1;
    hashmap_insert_elem(&services, &dummy_service_id, &dummy_service_info);
    // populate maglev table for the dummy service with a dummy backend
    struct maglev dummy_maglev = {0};
    for (int i = 0; i < MAGLEV_LOOKUP_SIZE; i++) {
      dummy_maglev.bkd_mapping[i] = 0; // point to the only backend
    }
    hashmap_insert_elem(&maglev_tables, &dummy_service_id, &dummy_maglev);
    // populate backends hashmap with a dummy entry
    struct backend_id dummy_bkd_id = {0};
    struct backend_info dummy_bkd_info = {0};
    dummy_bkd_id.service = dummy_service_id;
    dummy_bkd_id.index = 0;
    dummy_bkd_info.addr = inet_addr("10.129.2.121");
    dummy_bkd_info.port = htons(80);
    dummy_bkd_info.mac_addr[0] = 0x02;
    dummy_bkd_info.mac_addr[1] = 0x00;
    dummy_bkd_info.mac_addr[2] = 0x00;
    dummy_bkd_info.mac_addr[3] = 0x00;
    dummy_bkd_info.mac_addr[4] = 0x00;
    dummy_bkd_info.mac_addr[5] = 0x01; // MAC: 02:00:00:00:00:01
    dummy_bkd_info.port = 0; // assume backend is reachable via port 0
    hashmap_insert_elem(&backends, &dummy_bkd_id, &dummy_bkd_info);

  //struct backend_id bkdid = {
  //    .service = dummy_service_id,
  //    .index =
  //        ((struct maglev *)hashmap_lookup_elem(&maglev_tables, &dummy_service_id))
  //            ->bkd_mapping[murmurhash(&sid, sizeof(struct session_id), 0) %
  //                          MAGLEV_LOOKUP_SIZE]};
  //struct backend_info *bkdinfo = hashmap_lookup_elem(&backends, &bkdid);

    /* parse application arguments (after the EAL ones) */
    ret = parse_args(argc, argv);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "Invalid arguments\n");

    printf("MAC updating %s\n", mac_updating_flag ? "enabled" : "disabled");
    if (application == MICA || application == MICA_UDP)
      printf("MICA db size: %" PRIu64 " keys\n", mica_db_size);

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
    if (enabled_port_mask & ~((1 << nb_ports) - 1))
      rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
               (1 << nb_ports) - 1);

    /* reset dst_ports */
    for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
      dst_ports[portid] = 0;
    last_port = 0;

    /* populate destination port details */
    if (port_pair_params != NULL) {
      uint16_t idx, p;

      for (idx = 0; idx < (nb_port_pair_params << 1); idx++) {
        p = idx & 1;
        portid = port_pair_params[idx >> 1].port[p];
        dst_ports[portid] = port_pair_params[idx >> 1].port[p ^ 1];
      }
    } else {
      RTE_ETH_FOREACH_DEV(portid) {
        /* skip ports that are not enabled */
        if ((enabled_port_mask & (1 << portid)) == 0)
          continue;

        if (nb_ports_in_mask % 2) {
          dst_ports[portid] = last_port;
          dst_ports[last_port] = portid;
        } else {
          last_port = portid;
        }

        nb_ports_in_mask++;
      }
      if (nb_ports_in_mask % 2) {
        printf("Notice: odd number of ports in portmask.\n");
        dst_ports[last_port] = last_port;
      }
    }

    rx_lcore_id = 0;
    qconf = NULL;

    for (rx_lcore_id = 0; rx_lcore_id < RTE_MAX_LCORE; rx_lcore_id++) {
		  if (rte_lcore_is_enabled(rx_lcore_id) == 0)
			  continue;
		  nb_lcores++;
	  }
	  printf("Number of available lcores: %u\n", nb_lcores);
    if (rx_queue % nb_lcores !=0) {
      printf("num queue is not multiple of num lcores\n");
    }
    rx_queue_per_core=rx_queue/nb_lcores;

  /* Initialize the port/queue configuration of each logical core */
	RTE_ETH_FOREACH_DEV(portid)
	{
		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;
    int count_core=0;
		for (rx_lcore_id = 0; rx_lcore_id < RTE_MAX_LCORE; rx_lcore_id++) {
			if (rte_lcore_is_enabled(rx_lcore_id) == 0)
				continue;
			qconf = &lcore_queue_conf[rx_lcore_id];
			qconf->id=count_core++;
      qconf->n_rx_port++;
			qconf->rx_port_list[qconf->n_rx_port] = portid;
			printf("Lcore %u: RX port %u TX port %u\n", rx_lcore_id, portid, portid);
		}

	}

    /* Initialize the port/queue configuration of each logical core */
    /*RTE_ETH_FOREACH_DEV(portid) {
      // skip ports that are not enabled //
      if ((enabled_port_mask & (1 << portid)) == 0)
        continue;

      // get the lcore_id for this port //
      while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
             lcore_queue_conf[rx_lcore_id].n_rx_port == rx_queue) {
        rx_lcore_id++;
        if (rx_lcore_id >= RTE_MAX_LCORE)
          rte_exit(EXIT_FAILURE, "Not enough cores\n");
      }

      if (qconf != &lcore_queue_conf[rx_lcore_id]) {
        // Assigned a new logical core in the loop above. //
        qconf = &lcore_queue_conf[rx_lcore_id];
        nb_lcores++;
      }

      qconf->rx_port_list[qconf->n_rx_port] = portid;
      qconf->n_rx_port++;
      printf("Lcore %u: RX port %u TX port %u\n", rx_lcore_id, portid,
             dst_ports[portid]);
    }*/

    nb_mbufs = RTE_MAX(
        rx_queue * nb_ports *
            (nb_rxd + nb_txd + MAX_PKT_BURST + nb_lcores * MEMPOOL_CACHE_SIZE),
        8192U);
    printf("Creating mbuf pool with %u mbufs\n", nb_mbufs);

    /* create the mbuf pool */
    if (bypass) {
      for (uint32_t i = 0; i < rx_queue; i++) {
        char pool_name[32];
        snprintf(pool_name, sizeof(pool_name), "mbuf_pool_%d", i);
        nb_mbufs = nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
                               nb_lcores * MEMPOOL_CACHE_SIZE);

        pktmbuf_pool[i] =
            // rte_pktmbuf_pool_create(pool_name, nb_mbufs, MEMPOOL_CACHE_SIZE,
            // 0,
            //                         RTE_MBUF_DEFAULT_BUF_SIZE,
            //                         rte_socket_id());
            create_extbuf_pool(pool_name, nb_ports, 1, nb_rxd, nb_txd,
                               nb_lcores, rte_socket_id());
      }
    } else {
      for (uint32_t i = 0; i < rx_queue; i++) {
        if (!lifo) {
          pktmbuf_pool[i] = rte_pktmbuf_pool_create(
              "mbuf_pool", nb_mbufs, MEMPOOL_CACHE_SIZE, 0,
              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        } else {
          char pool_name[32];
          snprintf(pool_name, sizeof(pool_name), "mbuf_pool_%d", i);
          pktmbuf_pool[i] = rte_mempool_create_empty(
              pool_name, nb_mbufs,
              RTE_MBUF_DEFAULT_BUF_SIZE + sizeof(struct rte_mbuf),
              MEMPOOL_CACHE_SIZE, sizeof(struct rte_pktmbuf_pool_private),
              SOCKET_ID_ANY, rte_socket_id());
          if (pktmbuf_pool[i] == NULL) {
            // Check rte_errno for more details on the error
             rte_exit(EXIT_FAILURE, "Cannot create empty mempool for queue %u: %s\n", i,
                      rte_strerror(rte_errno));
          }

          if (rte_mempool_set_ops_byname(pktmbuf_pool[i], "stack", NULL) < 0)
            rte_panic("mempool_set_ops stack failed\n");

          struct rte_pktmbuf_pool_private *priv =
              rte_mempool_get_priv(pktmbuf_pool[i]);

          priv->mbuf_data_room_size = RTE_MBUF_DEFAULT_BUF_SIZE;
          priv->mbuf_priv_size = 0;

          if (rte_mempool_populate_default(pktmbuf_pool[i]) < 0)
            rte_panic("mempool_populate_default failed\n");
          rte_mempool_obj_iter(pktmbuf_pool[i], rte_pktmbuf_init, NULL);
        }
      }
    }

    /* Initialise each port */
    RTE_ETH_FOREACH_DEV(portid) {
      struct rte_eth_rxconf rxq_conf;
      struct rte_eth_txconf txq_conf;
      struct rte_eth_conf local_port_conf = port_conf;
      struct rte_eth_dev_info dev_info;

      /* skip ports that are not enabled */
      if ((enabled_port_mask & (1 << portid)) == 0) {
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
                 "Error during getting device (port %u) info: %s\n", portid,
                 strerror(-ret));

      struct rte_eth_dev *dev = &rte_eth_devices[portid];

      // qdma_reg_write_usr(dev,0x000C,1); //QDMA reset
      // qdma_reg_write_usr(dev,0x000C,2); //CMAC0 reset
      // qdma_reg_write_usr(dev,0x000C,4); //CMAC1 reset
      // rte_delay_ms(5000);

      // local_port_conf.rxmode.mq_mode              = ETH_MQ_RX_RSS;
      // local_port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP |
      // ETH_RSS_TCP | ETH_RSS_UDP;

      // modificare per mettere più code
      ret = rte_eth_dev_configure(portid, rx_queue,
                                  rx_queue, &local_port_conf);
      if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
                 ret, portid);

      // struct qdma_pci_dev *qdma_dev = dev->data->dev_private;
      uint32_t reg_offst = 0; // timestamp;
      uint32_t val = qdma_reg_read_usr(dev, reg_offst);
      // Timestamp--> QDMA Reg (0x0) Value: 0x28602ca
      // 29/01/2026 0xc5a366e
      printf("Timestamp--> QDMA Reg (0x%X) Value: 0x%X\n", reg_offst, val);
      uint32_t cfg_val = qdma_reg_read(
          dev,
          0xBE0); // QDMA_CFG_OFFSET 0x001f0040 --> prefech cache size 64 OK!
      printf("CFG VAL: 0x%08x\n", cfg_val);

      struct rte_eth_rss_reta_entry64 reta_conf[2048 / RTE_RETA_GROUP_SIZE];
      int i, j;
      // crea l'indir table con valori da 0 a rx_queue
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
        rte_exit(EXIT_FAILURE, "Cannot set RSS REA: err=%d, port=%u\n", ret,
                 portid);

      rte_eth_dev_rss_reta_query(portid, reta_conf, dev_info.reta_size);
      rx_queue = reta_conf[0].reta[0] + 1;
      printf("rx_queue: %d\n", rx_queue);

      rte_eth_dev_info_get(portid, &dev_info);

      ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
      if (ret < 0)
        rte_exit(EXIT_FAILURE,
                 "Cannot adjust number of descriptors: err=%d, "
                 "port=%u\n",
                 ret, portid);

      ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
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

      for (qid = 0; qid < rx_queue; qid++) {
        diag = rte_pmd_qdma_set_queue_mode(portid, qid,
                                           RTE_PMD_QDMA_STREAMING_MODE);
        if (diag < 0)
          rte_exit(EXIT_FAILURE,
                   "rte_pmd_qdma_set_queue_mode : "
                   "Passing of STREAMING_MODE "
                   "failed qid=%d\n",
                   qid);

        if (bypass) {
          rte_pmd_qdma_configure_rx_bypass(
              portid, qid, 2,
              0); // RTE_PMD_QDMA_RX_BYPASS_SIMPLE = 2,
          // Size 0 indicates internal mode descriptor size.
        } else {
          rte_pmd_qdma_configure_rx_bypass(
              portid, qid, 0,
              0); // RTE_PMD_QDMA_RX_BYPASS_NONE = 0,
        }
        if (toasty) {
          rte_pmd_qdma_enable_toasty_logic(portid, qid);
        }
        if (shring) {
          rte_pmd_qdma_enable_shring_logic(portid, qid);
        }
        if (bypass) {
          ret = rte_eth_rx_queue_setup(portid, qid, nb_rxd,
                                       rte_eth_dev_socket_id(portid), &rxq_conf,
                                       pktmbuf_pool[qid]);
        } else {
          ret = rte_eth_rx_queue_setup(portid, qid, nb_rxd,
                                       rte_eth_dev_socket_id(portid), &rxq_conf,
                                       pktmbuf_pool[0]);
        }
        if (ret < 0)
          rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
                   ret, portid);
        if (shring) {
          rte_pmd_qdma_set_shring(portid, qid, 0);
        }
            
        ret = rte_pmd_qdma_set_cmpt_overflow_check(portid, qid, !freerunning);
        if (ret < 0)
          rte_exit(EXIT_FAILURE,
                   "rte_pmd_qdma_set_cmpt_overflow_check:err=%d, port=%u\n",
                   ret, portid);

        if (bypass && (qid <= qmask)) {
          if (qdma_bypass_reg_get_prefetch_tag(dev, qid, &prefetch_tag[qid])) {
            printf("error reading prefetch tag\n");
            return -1;
          }
          prefetch_tag[qid] &= 0x7f;
          printf("Prefetch tag for qid=%d: %u\n", qid, prefetch_tag[qid]);
        }
        /* init one TX queue for eacxh RX queue */
        fflush(stdout);
        txq_conf = dev_info.default_txconf;
        txq_conf.offloads = local_port_conf.txmode.offloads;
        ret = rte_eth_tx_queue_setup(portid, qid, nb_txd,
                                     rte_eth_dev_socket_id(portid), &txq_conf);
        if (ret < 0)
          rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
                   ret, portid);

        /* Initialize TX buffers */
        tx_buffer[portid] = rte_zmalloc_socket(
            "tx_buffer", RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
            rte_eth_dev_socket_id(portid));
        if (tx_buffer[portid] == NULL)
          rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
                   portid);

        rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

        ret = rte_eth_tx_buffer_set_err_callback(
            tx_buffer[portid], rte_eth_tx_buffer_count_callback,
            &port_stats[portid][0].dropped);
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
      if (debug || debug_timestamp)
        qdma_write_bypass_reg_debug(dev, 1);
      else
        qdma_write_bypass_reg_debug(dev, 0);
      if (bypass) {
        qdma_reg_write_usr(dev, 0x5150, qmask); // qmask
        // qdma_reg_write_usr(dev,0x5154,0); //dsc_crdt_in_fence
        for (qid = 0; qid < rx_queue; qid++) {
          printf("---   Q=%d   ---\n", qid);
          print_phys(dev, qid);
          phys_addr = get_desc(dev, qid, 0);
          if (qid == 0)
            q0_phys_addr_start = phys_addr;
          if (qid == 1)
            q1_phys_addr_start = phys_addr;

          printf("Phys addr %08lx\n", phys_addr);
          qdma_write_direct2_queue_bypass_registers(
          //qdma_write_direct_queue_bypass_registers(
          //qdma_write_queue_bypass_registers(
              dev, qid, phys_addr, prefetch_tag[qid & qmask], 1, nb_rxd);
        }
        if (freerunning && (debug|| debug_timestamp))
          qdma_write_bypass_reg_debug(dev, 3);

        if (freerunning && !debug && !debug_timestamp)
          qdma_write_bypass_reg_debug(dev, 2);

        if (elastic && !debug && !debug_timestamp)
          qdma_write_bypass_reg_debug(dev, 4);

        if (elastic && (debug || debug_timestamp))
          qdma_write_bypass_reg_debug(dev, 5);

        // reset counters
        qdma_bypass_direct_clear_counters(dev);
        //qdma_bypass_clear_counters(dev);
      }

      printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n", portid,
             ports_eth_addr[portid].addr_bytes[0],
             ports_eth_addr[portid].addr_bytes[1],
             ports_eth_addr[portid].addr_bytes[2],
             ports_eth_addr[portid].addr_bytes[3],
             ports_eth_addr[portid].addr_bytes[4],
             ports_eth_addr[portid].addr_bytes[5]);

      /* initialize port stats */
      memset(&port_stats, 0, sizeof(port_stats));
    }

    if (!nb_ports_available) {
      rte_exit(EXIT_FAILURE,
               "All available ports are disabled. Please set portmask.\n");
    }

    // start

    cm = rte_zmalloc(NULL, sizeof(struct countmin), 64);
    cm->values = rte_zmalloc(NULL, sizeof(uint64_t *) * num_hash, 64);
    for (int i = 0; i < num_hash; i++) {
      cm->values[i] = rte_zmalloc(NULL, sizeof(uint64_t) * cms_columns, 64);
    }

    for (int i = 0; i < num_hash; i++) {
      for (uint32_t j = 0; j < cms_columns; j++) {
        cm->values[i][j] = 0;
      }
    }

    check_all_ports_link_status(enabled_port_mask);

    if (application == R2P2_ECHO || application == R2P2_STSS) {
      // ports_eth_addr[0] is only populated by the per-port init loop
      // above (rte_eth_macaddr_get()), so this can't run any earlier.
      r2p2_glue_global_init(r2p2_local_ip_be, r2p2_local_port_be,
                            &ports_eth_addr[0]);
      r2p2_set_recv_cb(application == R2P2_ECHO ? r2p2_glue_echo_recv
                                                 : r2p2_glue_stss_recv);
    }

    /* Initialize PCAP file for packet capture */
    if (dump)
      if (pcap_file_open("captured_packets.pcap") < 0) {
        printf("Warning: Could not open PCAP file for writing\n");
      }

    ret = 0;
    /* launch per-lcore init on every lcore */
    rte_eal_mp_remote_launch(launch_one_lcore, NULL, CALL_MAIN);
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
      if (rte_eal_wait_lcore(lcore_id) < 0) {
        ret = -1;
        break;
      }
    }

    printf("RX packets: %" PRIu64 "\n", stats.ipackets);
    printf("TX packets: %" PRIu64 "\n", stats.opackets);
    printf("RX dropped: %" PRIu64 "\n", stats.imissed);
    
    printf("measured time: %.2f seconds\n",
           (double)end_time / (double)rte_get_timer_hz());

    struct rte_eth_dev *dev = &rte_eth_devices[0];
    int val =
        qdma_reg_read_usr(dev, 0x512C); // start from 1 to sync with CMPL id
    printf("PKT COUNTER VAL: %d\n", val);

    // save countmin in a file
    /*FILE *fp;
    fp = fopen("countmin.txt", "w");
    for (int i = 0; i < num_hash; i++) {
      for (int j = 0; j < cms_columns; j++) {
        fprintf(fp, "%lu\n", cm->values[i][j]);
        // printf("%lu\n", cm->values[i][j]);
      }
    }
    fclose(fp);*/

    if (bypass) {
      for (uint32_t qid = 0; qid < rx_queue; qid++) {
        qdma_write_direct2_queue_bypass_registers(dev, qid, 0x0, 0, 0, 0);
        //qdma_write_direct_queue_bypass_registers(dev, qid, 0x0, 0, 0, 0);
        //qdma_write_queue_bypass_registers(dev, qid, 0x0, 0, 0, 0);
      }
    }

    RTE_ETH_FOREACH_DEV(portid) {
      if ((enabled_port_mask & (1 << portid)) == 0)
        continue;
      printf("Closing port %d...", portid);
      ret = rte_eth_dev_stop(portid);
      if (ret != 0)
        printf("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);
      rte_eth_dev_close(portid);
      printf(" Done\n");
    }
    printf("Bye...\n");

    /* Close PCAP file */
    if (dump)
      pcap_file_close();

    // free countmin
    for (int i = 0; i < num_hash; i++) {
      rte_free(cm->values[i]);
    }
    rte_free(cm->values);
    rte_free(cm);

    /* Release EAL/VFIO/hugepage state (never called before this fix) so the
     * QDMA device is fully quiesced before the process exits. */
    rte_eal_cleanup();

    return ret;
  }

  


  
