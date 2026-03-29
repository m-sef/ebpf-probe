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

/**
 * @brief 
 * 
 */
void perf_event_handler__init();

/**
 * @brief 
 * 
 * @param event 
 * @param pid 
 * @param cpu 
 */
void perf_event_handler__open_hardware_event(
		uint64_t event,
		pid_t pid,
		int cpu);

/**
 * @brief 
 * 
 * @param event 
 * @param pid 
 */
void perf_event_handler__open_hardware_event_across_all_cpus(
		uint64_t event,
		pid_t pid);

/**
 * @brief 
 * 
 * @param event 
 * @param cpu 
 */
void perf_event_handler__reset_hardware_event(
		uint64_t event,
		int cpu);

/**
 * @brief 
 * 
 * @param event 
 */
void perf_event_handler__reset_hardware_event_across_all_cpus(
		uint64_t event);

/**
 * @brief 
 * 
 * @param event 
 * @param cpu 
 */
void perf_event_handler__disable_hardware_event(
		uint64_t event,
		int cpu);

/**
 * @brief 
 * 
 * @param event 
 */
void perf_event_handler__disable_hardware_event_across_all_cpus(
		uint64_t event);

/**
 * @brief 
 * 
 * @param event 
 * @param cpu 
 */
void perf_event_handler__enable_hardware_event(
		uint64_t event,
		int cpu);

/**
 * @brief 
 * 
 * @param event 
 */
void perf_event_handler__enable_hardware_event_across_all_cpus(
		uint64_t event);

/**
 * @brief 
 * 
 * @todo event is never removed from perf_event_handler.perf_event_map, potential memory leak
 * @param event 
 * @param cpu 
 */
void perf_event_handler__close_hardware_event(
		uint64_t event,
		int cpu);

/**
 * @brief 
 * 
 * @todo event is never removed from perf_event_handler.perf_event_map, potential memory leak
 * @param event 
 */
void perf_event_handler__close_hardware_event_across_all_cpus(
		uint64_t event);

/**
 * @brief 
 * 
 * @param event 
 * @param cpu 
 * @return uint64_t 
 */
uint64_t perf_event_handler__read_hardware_event(
		uint64_t event,
		int cpu);

/**
 * @brief 
 * 
 * @param event 
 * @return uint64_t 
 */
uint64_t perf_event_handler__read_hardware_event_across_all_cpus(
		uint64_t event);

#endif