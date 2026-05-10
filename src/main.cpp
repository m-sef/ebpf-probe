#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>

#include "definitions.hpp"
#include "userspace_loader.hpp"

const char short_options[] = "hi:v";

const static struct option long_options[] = {
    {"help",      no_argument,       nullptr, 'h'},
    {"interface", required_argument, nullptr, 'i'},
    {"verbose",   no_argument,       nullptr, 'v'},
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
    fprintf(stderr, "usage: %s -i interface [-h][-v]\n", program_name);
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
            options.interface_name = optarg;
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

    /* err = ebpf_probe::init(options);
    if (err != EXIT_SUCCESS)
    {
        ebpf_probe::destroy();
        return err;
    }

    err = ebpf_probe::attach_xdp(options.interface_name);
    if (err != EXIT_SUCCESS)
    {
        ebpf_probe::destroy();
        return err;
    }

    signal(SIGINT, handle_signal_interrupt);

    while (running)
        sleep(5);

    ebpf_probe::destroy();
    puts(""); */

    UserspaceLoader userspace_loader(options);

    signal(SIGINT, handle_signal_interrupt);

    while (running)
        sleep(5);
    
    puts("");

    return EXIT_SUCCESS;
}