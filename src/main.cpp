#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>

#include "ebpf_probe.hpp"
#include "perf_event_handler.h"
#include "rapl_handler.h"

const char short_options[] = "hi:";

const static struct option long_options[] = {
    {"interface", required_argument, nullptr, 'i'},
    {"help",      no_argument,       nullptr, 'h'},
};

static struct {
    char* interface_name; /* Listen for packets on this network interface */
} configuration;

static volatile sig_atomic_t running = true;

static void
handle_signal_interrupt(
        const int sig)
{
    running = false;
}

static inline void
put_usage(
        char* program_name)
{
    fprintf(stderr, "usage: %s -i interface [-h]\n", program_name);
}

static inline void
put_help(
        char* program_name)
{
    put_usage(program_name);

    fprintf(stderr, "\noptions:\n");
    for (const struct option& opt : long_options)
    {
        fprintf(stderr, "  -%c, --%-18s\n", (char)opt.val, opt.name);
    }
}

static inline void
parse_arguments(
        int    argc,
        char** argv)
{
    int option_index = 0;
    int opt;

    while ((opt = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
    {
        switch (opt)
        {
        case 'h':
            put_help(argv[0]);
            exit(EXIT_FAILURE);
              
        case 'i':
            configuration.interface_name = optarg;
            break;
              
        default:
            put_usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (configuration.interface_name == nullptr)
    {
        put_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char** argv)
{
    error_t err;
    parse_arguments(argc, argv);

    err = ebpf_probe::init();
    if (err != EXIT_SUCCESS)
        return err;

    err = ebpf_probe::attach_xdp(configuration.interface_name);
    if (err != EXIT_SUCCESS)
        return err;

    signal(SIGINT, handle_signal_interrupt);

    perf_event_handler__init();
    rapl_handler__init();

    perf_event_handler__open_hardware_event_across_all_cpus(PERF_COUNT_HW_INSTRUCTIONS, -1);
    perf_event_handler__open_hardware_event_across_all_cpus(PERF_COUNT_HW_CPU_CYCLES, -1);
    perf_event_handler__open_hardware_event_across_all_cpus(PERF_COUNT_HW_REF_CPU_CYCLES, -1);
    perf_event_handler__open_hardware_event_across_all_cpus(PERF_COUNT_HW_CACHE_MISSES, -1);

    while (running)
    {
        double rapl_energy = rapl_handler__read_energy_counter_across_all_cpus(RAPL_PKG);

        printf("%ld,%ld,%ld,%ld,%ld,%f\n",
            ebpf_probe::get_total_rx_bytes_received(),
            perf_event_handler__read_hardware_event_across_all_cpus(PERF_COUNT_HW_INSTRUCTIONS),
            perf_event_handler__read_hardware_event_across_all_cpus(PERF_COUNT_HW_CPU_CYCLES),
            perf_event_handler__read_hardware_event_across_all_cpus(PERF_COUNT_HW_REF_CPU_CYCLES),
            perf_event_handler__read_hardware_event_across_all_cpus(PERF_COUNT_HW_CACHE_MISSES),
            rapl_energy);
        
        sleep(1);
    }

    perf_event_handler__close_hardware_event_across_all_cpus(PERF_COUNT_HW_INSTRUCTIONS);
    perf_event_handler__close_hardware_event_across_all_cpus(PERF_COUNT_HW_CPU_CYCLES);
    perf_event_handler__close_hardware_event_across_all_cpus(PERF_COUNT_HW_REF_CPU_CYCLES);
    perf_event_handler__close_hardware_event_across_all_cpus(PERF_COUNT_HW_CACHE_MISSES);

    ebpf_probe::destroy();
    puts("");

    return EXIT_SUCCESS;
}