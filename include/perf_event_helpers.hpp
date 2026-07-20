#ifndef PERF_EVENT_HELPERS_H
#define PERF_EVENT_HELPERS_H

#include <linux/perf_event.h>

#include <unordered_map>
#include <string>

#define FOREACH_PERF_EVENT(i) for (size_t i = 0; i < NUM_EVENT_TYPES; i++)

enum perf_events {
    CPU_CYCLES          = 0,
	INSTRUCTIONS        = 1,
    CACHE_REFERENCES    = 2,
    CACHE_MISSES        = 3,
    BRANCH_INSTRUCTIONS = 4,
    BRANCH_MISSES       = 5,
    BUS_CYCLES          = 6,
	REF_CPU_CYCLES      = 7,
	NUM_EVENT_TYPES,
};

[[maybe_unused]] static struct perf_event_attr perf_events[] = {
    [CPU_CYCLES]          = {.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_CPU_CYCLES},
    [INSTRUCTIONS]        = {.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_INSTRUCTIONS},
    [CACHE_REFERENCES]    = {.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_CACHE_REFERENCES},
    [CACHE_MISSES]        = {.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_CACHE_MISSES},
    [BRANCH_INSTRUCTIONS] = {.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
    [BRANCH_MISSES]       = {.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_BRANCH_MISSES},
    [BUS_CYCLES]          = {.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_BUS_CYCLES},
    [REF_CPU_CYCLES]      = {.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_REF_CPU_CYCLES},
};

[[maybe_unused]] static const char* perf_event_names[] = {
    [CPU_CYCLES]          = "cpu-cycles",
    [INSTRUCTIONS]        = "instructions",
    [CACHE_REFERENCES]    = "cache-references",
    [CACHE_MISSES]        = "cache-misses",
    [BRANCH_INSTRUCTIONS] = "branch-instructions",
    [BRANCH_MISSES]       = "branch-misses",
    [BUS_CYCLES]          = "bus-cycles",
    [REF_CPU_CYCLES]      = "ref-cycles",
};

inline std::unordered_map<std::string, enum perf_events> perf_event_name_to_event_id = {
    {"cpu-cycles",          CPU_CYCLES},
    {"instructions",        INSTRUCTIONS},
    {"cache-references",    CACHE_REFERENCES},
    {"cache-misses",        CACHE_MISSES},
    {"branch-instructions", BRANCH_INSTRUCTIONS},
    {"branch-misses",       BRANCH_MISSES},
    {"bus-cycles",          BUS_CYCLES},
    {"ref-cycles",          REF_CPU_CYCLES},
};

#endif