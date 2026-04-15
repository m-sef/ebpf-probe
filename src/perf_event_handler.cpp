/**
 * @file perf_event_handler.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief 
 * 
 */
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>

#include "perf_event_handler.h"

#define UNUSED_FD -1

typedef int fd_t;

static struct {
	struct { uint64_t key; fd_t* value; }* perf_event_map;
	size_t cpu_count;
} perf_event_handler;

static fd_t perf_event_open(
		struct perf_event_attr *hw_event,
		pid_t pid,
    	int cpu,
		int group_fd,
		unsigned long flags)
{
	return syscall(SYS_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

static void perf_event_set(
		fd_t fd,
		unsigned long request)
{
	assert(ioctl(fd, request, 0) == 0);
}

void perf_event_handler__init()
{
	perf_event_handler.cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
}

void perf_event_handler__open_hardware_event(
		uint64_t event,
		pid_t pid,
		int cpu)
{
	struct perf_event_attr pe = {
		.type = PERF_TYPE_HARDWARE,
		.size = sizeof(pe),
		.config = event
	};

	fd_t fd = perf_event_open(&pe, pid, cpu, -1, 0);
	if (fd == -1)
        err(EXIT_FAILURE, "Error opening leader %lx\n", event);
	
	fd_t* events = (fd_t*) malloc(perf_event_handler.cpu_count * sizeof(fd_t));
	memset(events, UNUSED_FD, perf_event_handler.cpu_count * sizeof(fd_t));

	events[cpu] = fd;

	perf_event_set(fd, PERF_EVENT_IOC_RESET);
	perf_event_set(fd, PERF_EVENT_IOC_ENABLE);
	
	hmput(perf_event_handler.perf_event_map, event, events);
}

void perf_event_handler__open_hardware_event_across_all_cpus(
		uint64_t event,
		pid_t pid)
{
	struct perf_event_attr pe = {
		.type = PERF_TYPE_HARDWARE,
		.size = sizeof(pe),
		.config = event
	};

	fd_t* events = (fd_t*) malloc(perf_event_handler.cpu_count * sizeof(fd_t));
	memset(events, UNUSED_FD, perf_event_handler.cpu_count * sizeof(fd_t));

	for (size_t i = 0; i < perf_event_handler.cpu_count; i++)
	{
		fd_t fd = perf_event_open(&pe, pid, i, -1, 0);
		if (fd == -1)
        	err(EXIT_FAILURE, "Error opening leader %lx\n", event);
		events[i] = fd;

		perf_event_set(fd, PERF_EVENT_IOC_RESET);
		perf_event_set(fd, PERF_EVENT_IOC_ENABLE);
	}

	hmput(perf_event_handler.perf_event_map, event, events);
}

void perf_event_handler__reset_hardware_event(
		uint64_t event,
		int cpu)
{
	assert(hmgeti(perf_event_handler.perf_event_map, event) != -1);
	assert(cpu < perf_event_handler.cpu_count);

	fd_t fd = hmget(perf_event_handler.perf_event_map, event)[cpu];
	assert(fd != UNUSED_FD);

	perf_event_set(fd, PERF_EVENT_IOC_RESET);
}

void perf_event_handler__reset_hardware_event_across_all_cpus(
		uint64_t event)
{
	assert(hmgeti(perf_event_handler.perf_event_map, event) != -1);

	fd_t* events = hmget(perf_event_handler.perf_event_map, event);
	fd_t* events_end = events + perf_event_handler.cpu_count;

	for (fd_t* ptr = events; ptr < events_end; ++ptr)
	{
		assert(*ptr != UNUSED_FD);
		perf_event_set(*ptr, PERF_EVENT_IOC_RESET);
	}
}

void perf_event_handler__disable_hardware_event(
		uint64_t event,
		int cpu)
{
	assert(hmgeti(perf_event_handler.perf_event_map, event) != -1);
	assert(cpu < perf_event_handler.cpu_count);

	fd_t fd = hmget(perf_event_handler.perf_event_map, event)[cpu];
	assert(fd != UNUSED_FD);

	perf_event_set(fd, PERF_EVENT_IOC_DISABLE);
}

void perf_event_handler__disable_hardware_event_across_all_cpus(
		uint64_t event)
{
	assert(hmgeti(perf_event_handler.perf_event_map, event) != -1);

	fd_t* events = hmget(perf_event_handler.perf_event_map, event);
	fd_t* events_end = events + perf_event_handler.cpu_count;

	for (fd_t* ptr = events; ptr < events_end; ++ptr)
	{
		assert(*ptr != UNUSED_FD);
		perf_event_set(*ptr, PERF_EVENT_IOC_DISABLE);
	}
}

void perf_event_handler__enable_hardware_event(
		uint64_t event,
		int cpu)
{
	assert(hmgeti(perf_event_handler.perf_event_map, event) != -1);
	assert(cpu < perf_event_handler.cpu_count);

	fd_t fd = hmget(perf_event_handler.perf_event_map, event)[cpu];
	assert(fd != UNUSED_FD);
	
	perf_event_set(fd, PERF_EVENT_IOC_ENABLE);
}

void perf_event_handler__enable_hardware_event_across_all_cpus(
		uint64_t event)
{
	assert(hmgeti(perf_event_handler.perf_event_map, event) != -1);

	fd_t* events = hmget(perf_event_handler.perf_event_map, event);
	fd_t* events_end = events + perf_event_handler.cpu_count;

	for (fd_t* ptr = events; ptr < events_end; ++ptr)
	{
		assert(*ptr != UNUSED_FD);
		perf_event_set(*ptr, PERF_EVENT_IOC_ENABLE);
	}
}

void perf_event_handler__close_hardware_event(
		uint64_t event,
		int cpu)
{
	assert(hmgeti(perf_event_handler.perf_event_map, event) != -1);
	assert(cpu < perf_event_handler.cpu_count);

	fd_t fd = hmget(perf_event_handler.perf_event_map, event)[cpu];
	assert(fd != UNUSED_FD);

	assert(close(fd) == 0);
	
	hmget(perf_event_handler.perf_event_map, event)[cpu] = UNUSED_FD;
}

void perf_event_handler__close_hardware_event_across_all_cpus(
		uint64_t event)
{
	assert(hmgeti(perf_event_handler.perf_event_map, event) != -1);

	fd_t* events = hmget(perf_event_handler.perf_event_map, event);
	fd_t* events_end = events + perf_event_handler.cpu_count;

	for (fd_t* ptr = events; ptr < events_end; ++ptr)
	{
		assert(*ptr != UNUSED_FD);
		assert(close(*ptr) == 0);
		*ptr = UNUSED_FD;
	}
}

uint64_t perf_event_handler__read_hardware_event(
		uint64_t event,
		int cpu)
{
	assert(hmgeti(perf_event_handler.perf_event_map, event) != -1);
	assert(cpu < perf_event_handler.cpu_count);

	fd_t fd = hmget(perf_event_handler.perf_event_map, event)[cpu];
	assert(fd != UNUSED_FD);
	
	uint64_t value;

	perf_event_set(fd, PERF_EVENT_IOC_DISABLE);
	assert(read(fd, &value, sizeof(value)) == sizeof(value));
	perf_event_set(fd, PERF_EVENT_IOC_ENABLE);
	
	return value;
}

uint64_t perf_event_handler__read_hardware_event_across_all_cpus(
		uint64_t event)
{
	assert(hmgeti(perf_event_handler.perf_event_map, event) != -1);

	uint64_t total_value = 0;

	fd_t* events = hmget(perf_event_handler.perf_event_map, event);
	fd_t* events_end = events + perf_event_handler.cpu_count;

	for (fd_t* ptr = events; ptr < events_end; ++ptr)
	{
		assert(*ptr != UNUSED_FD);

		uint64_t value;

		perf_event_set(*ptr, PERF_EVENT_IOC_DISABLE);
		assert(read(*ptr, &value, sizeof(value)) == sizeof(value));
		perf_event_set(*ptr, PERF_EVENT_IOC_ENABLE);

		total_value += value;
	}

	return total_value;
}