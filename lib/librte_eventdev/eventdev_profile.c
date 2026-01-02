#include "eventdev_profile.h"

/**
 * Hook callback to trace rte_event_dequeue_burst() calls.
 * This is needed to enable Event device profiling with
 * Intel(R) VTune Profiler.
 */
uint16_t
profile_hook_event_dequeue_burst(
		__rte_unused uint8_t dev_id, __rte_unused uint8_t port_id,
		__rte_unused uint16_t nb_events, uint16_t nb_dequeued_events)
{
	return nb_dequeued_events;
}