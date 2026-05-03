#ifndef COMMON_DEFINITIONS_H
#define COMMON_DEFINITIONS_H

#define LENGTH_OF(a) (sizeof(a) / sizeof((a)[0]))

typedef int fd_t;

typedef struct options {
    char* interface_name; /* Listen for packets on this network interface */
    int sample_frequency;
    bool verbose;
} options_t;

#endif