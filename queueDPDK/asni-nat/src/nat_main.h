#pragma once
#include <stdlib.h>
#include <stdint.h>

#include "nat_config.h"
#include "flow.h"
#include "nat_flowmanager.h"
#include "nf-log.h"
#include "nf-util.h"
#include "nf.h"
#include "utils/utils.h"
#include "utils/vigor-time.h"


#define EXPLICIT_DROP (1 << 16) - 1

int nf_process(uint16_t device, 
                uint8_t *payload,
                uint16_t ether_type,
                uint8_t ip_proto,
                uint32_t ip_src,
                uint32_t ip_dst,
                uint16_t port_src,
                uint16_t port_dst,
                vigor_time_t now);
