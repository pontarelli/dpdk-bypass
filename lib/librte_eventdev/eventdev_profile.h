#ifndef _RTE_EVENTDEV_PROFILE_H_
#define _RTE_EVENTDEV_PROFILE_H_

#include <rte_common.h>

/**
 * Hook callback to trace rte_event_dequeue_burst() calls.
 */
uint16_t
profile_hook_event_dequeue_burst(uint8_t dev_id, uint8_t port_id,
		uint16_t nb_events, uint16_t nb_dequeued_events);

#endif