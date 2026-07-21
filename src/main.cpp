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

options_t options = {};

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
    app.add_option("-f,--frequency", options.frequency,
        "Sample at this frequency per second for each CPU")
        ->default_val(20);
    app.add_flag("-v,--verbose", options.verbose,
        "Enable verbose output")
        ->default_val(false);

    CLI11_PARSE(app, argc, argv);

    try {
        UserspaceLoader userspace_loader;
        userspace_loader.init();

        while (running)
            pause();
        
        puts("");
    } catch (const std::runtime_error& err) {
        std::cout << std::format("[{} ERROR] {}", __FILE_NAME__, err.what()) << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}