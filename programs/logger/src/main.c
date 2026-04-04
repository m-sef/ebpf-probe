#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <stdbool.h>

#include "perf_event_handler.h"
#include "rapl_handler.h"
#include "xdp_probe.h"

#define REQUIRED_ARGS \
	REQUIRED_STRING_ARG(interface, "interface", "Listen on this interface")

#define BOOLEAN_ARGS \
    BOOLEAN_ARG(help, "-h", "Show help")

#include "easyargs.h"

static volatile sig_atomic_t running = true;

static void handle_signal_interrupt(const int sig)
{
	running = false;
}

int main(int argc, char** argv)
{
	struct timespec ts;
	args_t args = make_default_args();

	if (!parse_args(argc, argv, &args) || args.help)
	{
        print_help(argv[0]);
        return EXIT_FAILURE;
    }

	perf_event_handler__init();
	rapl_handler__init();
	xdp_probe__init();
	xdp_probe__attach(args.interface);

	perf_event_handler__open_hardware_event_across_all_cpus(PERF_COUNT_HW_INSTRUCTIONS, -1);
	perf_event_handler__open_hardware_event_across_all_cpus(PERF_COUNT_HW_CPU_CYCLES, -1);
	perf_event_handler__open_hardware_event_across_all_cpus(PERF_COUNT_HW_REF_CPU_CYCLES, -1);
	perf_event_handler__open_hardware_event_across_all_cpus(PERF_COUNT_HW_CACHE_MISSES, -1);

	signal(SIGINT, handle_signal_interrupt);
	
	while (running)
	{
		printf("%ld,%ld,%ld,%ld,%ld,%f\n",
			xdp_probe__get_total_rx_bytes_received(),
			perf_event_handler__read_hardware_event_across_all_cpus(PERF_COUNT_HW_INSTRUCTIONS),
			perf_event_handler__read_hardware_event_across_all_cpus(PERF_COUNT_HW_CPU_CYCLES),
			perf_event_handler__read_hardware_event_across_all_cpus(PERF_COUNT_HW_REF_CPU_CYCLES),
			perf_event_handler__read_hardware_event_across_all_cpus(PERF_COUNT_HW_CACHE_MISSES),
			rapl_handler__read_energy_counter_across_all());

		sleep(1);
	}

	perf_event_handler__close_hardware_event_across_all_cpus(PERF_COUNT_HW_INSTRUCTIONS);
	perf_event_handler__close_hardware_event_across_all_cpus(PERF_COUNT_HW_CPU_CYCLES);
	perf_event_handler__close_hardware_event_across_all_cpus(PERF_COUNT_HW_REF_CPU_CYCLES);
	perf_event_handler__close_hardware_event_across_all_cpus(PERF_COUNT_HW_CACHE_MISSES);

	xdp_probe__destroy();

	return EXIT_SUCCESS;
}