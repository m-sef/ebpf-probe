/**
 * @file definitions.hpp
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#ifndef COMMON_DEFINITIONS_H
#define COMMON_DEFINITIONS_H

#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <format>

typedef struct options {
    std::vector<std::string> interface;
    std::vector<std::string> event;
    std::vector<std::string> rapl;
    int sample_interval;
    int frequency;
    bool verbose;
} options_t;

extern options_t options;

#define INFO_PREFIX std::format("[{} INFO] ", __FILE_NAME__)
#define WARNING_PREFIX std::format("[{} WARNING] ", __FILE_NAME__)

#define INFO(message, ...) \
do { \
    std::cout << INFO_PREFIX << std::format(message, ##__VA_ARGS__) << std::endl; \
} while (0)

#define INFOV(message, ...) \
do { \
    if (options.verbose) \
        std::cout << INFO_PREFIX << std::format(message, ##__VA_ARGS__) << std::endl; \
} while(0)

#define WARNING(message, ...) \
do { \
    std::cout << WARNING_PREFIX << std::format(message, ##__VA_ARGS__) << std::endl; \
} while (0)

#define WARNINGV(message, ...) \
do { \
    if (options.verbose) \
        std::cout << WARNING_PREFIX << std::format(message, ##__VA_ARGS__) << std::endl; \
} while(0)

#define ERROR(message, ...) \
do { \
    throw std::runtime_error(std::format(message, ##__VA_ARGS__)); \
} while(0)

typedef int fd_t;
typedef unsigned int cpu_t;

#endif