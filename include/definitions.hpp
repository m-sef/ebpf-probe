/**
 * @file definitions.hpp
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#ifndef COMMON_DEFINITIONS_H
#define COMMON_DEFINITIONS_H

#include <string>

#define LENGTH_OF(a) (sizeof(a) / sizeof((a)[0]))

#define INFO(message, ...) \
do { \
    fprintf(stdout, "[INFO] "); \
    fprintf(stdout, message, ##__VA_ARGS__); \
} while (0)

#define WARNING(message, ...) \
do { \
    fprintf(stderr, "[WARNING] "); \
    fprintf(stderr, message, ##__VA_ARGS__); \
} while (0)

#define ERROR(message, ...) \
do { \
    fprintf(stderr, "[ERROR] "); \
    fprintf(stderr, message, ##__VA_ARGS__); \
} while (0)

typedef struct options {
    std::string interface_name; /* Listen for packets on this network interface */
    int sample_frequency;
    bool verbose;
} options_t;

#endif