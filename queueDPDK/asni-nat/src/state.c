#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include "state.h"
#include "flow.h"
#include "utils/map.h"
#include "utils/vector.h"
#include "utils/double-chain.h"


bool key_equals(void *k1, void *k2){
  uint16_t key1 = *((uint16_t *)k1);
  uint16_t key2 = *((uint16_t *)k2);
  return key1 == key2;
}

unsigned key_hash(void *k){
  uint16_t key = *((uint16_t *)k);
  return key;
}

void vector_init_element(void *elem){
  struct FlowId *flow_id = (struct FlowId *)elem;
  flow_id->src_ip = 0;
  flow_id->dst_ip = 0;
  flow_id->src_port = 0;
  flow_id->dst_port = 0;
  flow_id->protocol = 0;
}

struct State *alloc_state(uint16_t max_flows, uint16_t starting_port,
                          uint32_t nat_ip, uint16_t nat_device) {
  struct State *state = (struct State *)malloc(sizeof(struct State));
  if (state == NULL) {
    return NULL;
  }
  // Allocate Map
  state->fm = calloc(1, sizeof(struct Map *));
  if (state->fm == NULL) {
    free(state);
    return NULL;
  }
  int res = map_allocate(key_equals, key_hash, max_flows, &state->fm);
  if (res != 1) {
    free(state->fm);
    free(state);
    printf("Error allocating map\n");
    return NULL;
  }
  // Allocate vector
  state->fv = calloc(1, sizeof(struct Vector *));
  if (state->fv == NULL) {
    free(state->fm);
    free(state);
    return NULL;
  }
  res = vector_allocate(sizeof(struct FlowId), max_flows, vector_init_element, &state->fv);
  if (res != 1) {
    free(state->fm);
    free(state->fv);
    free(state);
    printf("Error allocating vector\n");
    return NULL;
  }
  // Allocate heap
  state->heap = calloc(1, sizeof(struct DoubleChain *));
  if (state->heap == NULL) {
    free(state->fm);
    free(state->fv);
    free(state);
    return NULL;
  }
  res = dchain_allocate(max_flows, &state->heap);
  if (res != 1) {
    free(state->fm);
    free(state->fv);
    free(state->heap);
    free(state);
    printf("Error allocating heap\n");
    return NULL;
  }
  
  
  // Keep other values in memory
  state->max_flows = max_flows;
  state->start_port = starting_port;
  state->nat_ip = nat_ip;
  state->nat_device = nat_device;
  return state;
}
