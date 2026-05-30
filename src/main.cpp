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

static struct options options = {};

static volatile sig_atomic_t running = true;

static void
handle_signal_interrupt(
        const int sig)
{
    running = false;
}

int main(int argc, char** argv)
{
    CLI::App app{DESCRIPTION, argv[0]};

    app.add_option("-i,--interface", options.interface_name, 
        "Listen for network traffic on this interface")->required();
    app.add_option("-f,--frequency", options.sample_frequency,
        "Sample at this frequency per second for each CPU (default: 1)")->default_val(1);
    app.add_flag("-v,--verbose", options.verbose,
        "Verbose output (default: false)")->default_val(false);
    
    CLI11_PARSE(app, argc, argv);

    UserspaceLoader userspace_loader(options);
    userspace_loader.init();

    signal(SIGINT, handle_signal_interrupt);

    while (running)
        pause();
    
    puts("");

    return EXIT_SUCCESS;
}