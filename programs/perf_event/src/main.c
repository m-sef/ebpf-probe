/**
 * @file main.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief 
 * 
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <stdbool.h>

#include "perf_event_handler.h"

static volatile sig_atomic_t running = true;

static void handle_signal_interrupt(const int sig)
{
	running = false;
}

int main(int argc, char** argv)
{
	signal(SIGINT, handle_signal_interrupt);

	uint64_t event = PERF_COUNT_HW_CACHE_MISSES;
	size_t cpu_count = sysconf(_SC_NPROCESSORS_ONLN);

	perf_event_handler__init();
	perf_event_handler__open_hardware_event_across_all_cpus(event, -1);

	while (running)
	{
		puts("");

		uint64_t total_value = 0;

		for (size_t cpu = 0; cpu < cpu_count; cpu++)
		{
			uint64_t value = perf_event_handler__read_hardware_event(event, cpu);

			printf("CPU %-2lu Cache misses: %lu\n", cpu, value);

			total_value += value;
		}

		printf(" Total cache misses: %lu\n", perf_event_handler__read_hardware_event_across_all_cpus(event));
		printf("                     %lu\n", total_value);

		perf_event_handler__reset_hardware_event_across_all_cpus(event);

		usleep(1000000);
	}

	perf_event_handler__close_hardware_event_across_all_cpus(event);

	return EXIT_SUCCESS;
}