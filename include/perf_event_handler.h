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

#include "stb_ds.h"

void perf_event_handler__init();

void perf_event_handler__open_hardware_event(
		uint64_t event,
		pid_t pid,
		int cpu);

void perf_event_handler__open_hardware_event_across_all_cpus(
		uint64_t event,
		pid_t pid);

void perf_event_handler__reset_hardware_event(
		uint64_t event,
		int cpu);

void perf_event_handler__reset_hardware_event_across_all_cpus(
		uint64_t event);

void perf_event_handler__disable_hardware_event(
		uint64_t event,
		int cpu);

void perf_event_handler__disable_hardware_event_across_all_cpus(
		uint64_t event);

void perf_event_handler__enable_hardware_event(
		uint64_t event,
		int cpu);

void perf_event_handler__enable_hardware_event_across_all_cpus(
		uint64_t event);

void perf_event_handler__close_hardware_event(
		uint64_t event,
		int cpu);

void perf_event_handler__close_hardware_event_across_all_cpus(
		uint64_t event);

uint64_t perf_event_handler__read_hardware_event(
		uint64_t event,
		int cpu);

uint64_t perf_event_handler__read_hardware_event_across_all_cpus(
		uint64_t event);

#endif