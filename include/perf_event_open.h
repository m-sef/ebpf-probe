/**
 * @file perf_event_open.h
 * @brief https://man7.org/linux/man-pages/man2/perf_event_open.2.html
 * 
 */
#ifndef PERF_EVENT_OPEN_H
#define PERF_EVENT_OPEN_H

#include <sys/syscall.h>
#include <unistd.h>

static inline long
perf_event_open(
    struct perf_event_attr* hw_event, pid_t pid,
    int cpu, int group_fd, unsigned long flags)
{
    int ret;

    ret = syscall(SYS_perf_event_open, hw_event, pid, cpu, group_fd, flags);

    return ret;
}


#endif