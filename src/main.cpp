/**
 * @file main.cpp
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>

#include "definitions.hpp"
#include "userspace_loader.hpp"

#include "CLI11.hpp"

#define DESCRIPTION \
"An XDP-based packet counter with per-CPU hardware performance counter \
and energy (RAPL) collection. Metrics are written to pinned BPF iterator files \
under /sys/fs/bpf/ebpf_probe/ and can be read with standard shell tools."

#define NAME "ebpf_probe"

options_t options = {
    .interface       = {},
    .event           = { "instructions", "cpu-cycles", "ref-cpu-cycles", "cache-misses" },
    .rapl            = { "pkg", "cores", "uncore", "ram", "psys" },
    .sample_interval = 1000,
};

static volatile sig_atomic_t running = true;

static void
handle_signal_interrupt(
        const int sig)
{
    running = false;
}

int main(int argc, char** argv)
{
    signal(SIGINT,  handle_signal_interrupt);
    signal(SIGTERM, handle_signal_interrupt);
    signal(SIGHUP,  handle_signal_interrupt);
    signal(SIGQUIT, handle_signal_interrupt);

    CLI::App app{DESCRIPTION, NAME};

    app.add_option("-i,--interface", options.interface, 
        "Monitor the network traffic on this interface(s)")
        ->required();
    app.add_option("-e,--event", options.event,
        "Events")
        ->capture_default_str();
    app.add_option("-r,--rapl", options.rapl,
        "RAPL")
        ->capture_default_str();
    app.add_option("-f,--frequency", options.frequency,
        "Sample at this frequency per second for each CPU")
        ->default_val(20);
    app.add_flag("-v,--verbose", options.verbose,
        "Enable verbose output")
        ->default_val(false);
    
    app.add_option("-s,--sample-interval", options.sample_interval,
        "Sample interval (milliseconds)")
        ->default_val(1000);
    
    CLI11_PARSE(app, argc, argv);

    UserspaceLoader userspace_loader;
    userspace_loader.init();

    while (running)
        pause();
    
    puts("");

    return EXIT_SUCCESS;
}