#ifndef RAPL_HANDLER_H
#define RAPL_HANDLER_H

#include <stdint.h>

enum rapl_domain {
	RAPL_PKG = 0,   // Package domain (entire CPU socket)
	RAPL_CORE,      // Core domain (CPU cores only)
	RAPL_UNCORE,    // Uncore domain (integrated GPU, memory controller)
	RAPL_DRAM,      // DRAM domain (memory)
	RAPL_PSYS,      // Platform domain (entire SoC)
	RAPL_MAX_DOMAINS
};

void rapl_handler__init();

double rapl_handler__read_energy_counter(int cpu, int domain);
double rapl_handler__read_energy_counter_across_all_cpus(int domain);
double rapl_handler__read_energy_counter_across_all_domains(int cpu);
double rapl_handler__read_energy_counter_across_all();

#endif