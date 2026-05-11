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

const char short_options[] = "f:hi:v";

const static struct option long_options[] = {
    {"help",      no_argument,       nullptr, 'h'},
    {"interface", required_argument, nullptr, 'i'},
    {"frequency", required_argument, nullptr, 'f'},
    {"verbose",   no_argument,       nullptr, 'v'},
    {0, 0, 0, 0},
};

const static char* long_option_descriptions[] = {
    "Display help message",
    "Listen for network traffic on this interface",
    "Frequency to sample perf and rapl events in Hz",
    "Verbose output when reading pinned files",
};

static struct options options = {
    .interface_name = nullptr,
    .sample_frequency = 1,
    .verbose = false,
};

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
    fprintf(stdout, "usage: %s -i INTERFACE [-f FREQUENCY] [-hv]\n", program_name);
}

static inline void
put_help(
        char* program_name)
{
    put_usage(program_name);

    fprintf(stdout, "\noptions:\n");
    for (size_t i = 0; i < LENGTH_OF(long_options) - 1; i++)
    {
        fprintf(stdout, "  -%c, --%-18s %s\n",
            (char)long_options[i].val,
            long_options[i].name,
            long_option_descriptions[i]);
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
            exit(EXIT_SUCCESS);
              
        case 'i':
            options.interface_name = optarg;
            break;
        
        case 'f':
            options.sample_frequency = atoi(optarg);
            break;
        
        case 'v':
            options.verbose = true;
            break;
              
        default:
            put_usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (options.interface_name == nullptr)
    {
        put_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char** argv)
{
    parse_arguments(argc, argv);

    UserspaceLoader userspace_loader(options);
    userspace_loader.init();

    signal(SIGINT, handle_signal_interrupt);

    while (running)
        pause();
    
    puts("");

    return EXIT_SUCCESS;
}