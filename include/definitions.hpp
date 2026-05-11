/**
 * @file definitions.hpp
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#ifndef COMMON_DEFINITIONS_H
#define COMMON_DEFINITIONS_H

#define LENGTH_OF(a) (sizeof(a) / sizeof((a)[0]))

#define INFO(message, ...) \
    fprintf(stdout, "[INFO] "); \
    fprintf(stdout, message, ##__VA_ARGS__)

#define WARNING(message, ...) \
    fprintf(stderr, "[WARNING] "); \
    fprintf(stderr, message, ##__VA_ARGS__)

#define ERROR(message, ...) \
    fprintf(stderr, "[ERROR] "); \
    fprintf(stderr, message, ##__VA_ARGS__);

typedef struct options {
    char* interface_name; /* Listen for packets on this network interface */
    int sample_frequency;
    bool verbose;
} options_t;

#endif