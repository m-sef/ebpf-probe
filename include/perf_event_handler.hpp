/**
 * @file perf_event_handler.h
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief 
 * 
 */
#ifndef PERF_EVENT_HANDLER_H
#define PERF_EVENT_HANDLER_H

#include <linux/perf_event.h>
#include <sys/types.h>
#include <stdint.h>

namespace perf_event_handler
{
    void init();

    void open_hardware_event(uint64_t event, pid_t pid, int cpu);
    void open_hardware_event_across_all_cpus(uint64_t event, pid_t pid);

    void reset_hardware_event(uint64_t event, int cpu);
    void reset_hardware_event_across_all_cpus(uint64_t event);

    void disable_hardware_event(uint64_t event, int cpu);
    void disable_hardware_event_across_all_cpus(uint64_t event);

    void enable_hardware_event(uint64_t event, int cpu);
    void enable_hardware_event_across_all_cpus(uint64_t event);

    void close_hardware_event(uint64_t event, int cpu);
    void close_hardware_event_across_all_cpus(uint64_t event);

    uint64_t read_hardware_event(uint64_t event, int cpu);
    uint64_t read_hardware_event_across_all_cpus(uint64_t event);
}

#endif