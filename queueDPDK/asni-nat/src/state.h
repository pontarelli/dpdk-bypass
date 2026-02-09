#pragma once
#include <stdint.h>

struct State {
  struct Map *fm;
  struct Vector *fv;
  struct DoubleChain *heap;
  uint16_t start_port;
  uint32_t nat_ip;
  uint16_t nat_device;
  uint16_t max_flows;
  struct lpm *lpm;
};

struct State *alloc_state(uint16_t max_flows, uint16_t starting_port,
                          uint32_t nat_ip, uint16_t nat_device);