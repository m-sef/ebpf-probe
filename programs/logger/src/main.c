#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <stdbool.h>

#include "perf_event_handler.h"
#include "xdp_probe.h"

static volatile sig_atomic_t running = true;

static void handle_signal_interrupt(const int sig)
{
	running = false;
	puts("");
}

int main(int argc, char** argv)
{
	signal(SIGINT, handle_signal_interrupt);

	perf_event_handler__init();
	xdp_probe__init();
	xdp_probe__attach("enp0s31f6");

	perf_event_handler__open_hardware_event_across_all_cpus(PERF_COUNT_HW_INSTRUCTIONS, -1);
	perf_event_handler__open_hardware_event_across_all_cpus(PERF_COUNT_HW_CPU_CYCLES, -1);
	perf_event_handler__open_hardware_event_across_all_cpus(PERF_COUNT_HW_REF_CPU_CYCLES, -1);
	perf_event_handler__open_hardware_event_across_all_cpus(PERF_COUNT_HW_CACHE_MISSES, -1);
	perf_event_handler__open_hardware_event_across_all_cpus(29, -1); // EVIL
	
	while (running)
	{
		printf("%ld,%ld,%ld,%ld,%ld,%ld\n",
			xdp_probe__get_total_rx_bytes_received(),
			perf_event_handler__read_hardware_event_across_all_cpus(PERF_COUNT_HW_INSTRUCTIONS),
			perf_event_handler__read_hardware_event_across_all_cpus(PERF_COUNT_HW_CPU_CYCLES),
			perf_event_handler__read_hardware_event_across_all_cpus(PERF_COUNT_HW_REF_CPU_CYCLES),
			perf_event_handler__read_hardware_event_across_all_cpus(PERF_COUNT_HW_CACHE_MISSES),
			perf_event_handler__read_hardware_event_across_all_cpus(29));

		sleep(1);
	}

	perf_event_handler__close_hardware_event_across_all_cpus(PERF_COUNT_HW_INSTRUCTIONS);
	perf_event_handler__close_hardware_event_across_all_cpus(PERF_COUNT_HW_CPU_CYCLES);
	perf_event_handler__close_hardware_event_across_all_cpus(PERF_COUNT_HW_REF_CPU_CYCLES);
	perf_event_handler__close_hardware_event_across_all_cpus(PERF_COUNT_HW_CACHE_MISSES);
	perf_event_handler__close_hardware_event_across_all_cpus(29);

	xdp_probe__destroy();

	return EXIT_SUCCESS;
}