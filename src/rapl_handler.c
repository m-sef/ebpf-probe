#include "rapl_handler.h"

#include <linux/perf_event.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

#include "common_definitions.h"

static const char* rapl_domain_names[] = {
	[RAPL_PKG]    = "pkg",
	[RAPL_CORE]   = "cores",
	[RAPL_UNCORE] = "uncore",
	[RAPL_DRAM]   = "ram",
	[RAPL_PSYS]   = "psys",
};

static fd_t rapl_file_descriptors[256][RAPL_MAX_DOMAINS];
static double rapl_scale = 0.0;
static size_t cpu_count = 0;

static fd_t perf_event_open(
		struct perf_event_attr *hw_event,
		pid_t pid,
    	int cpu,
		int group_fd,
		unsigned long flags)
{
	return syscall(SYS_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

static int read_rapl_type()
{
	FILE* file;
	int type = -1;

	file = fopen("/sys/bus/event_source/devices/power/type", "r");
	if (!file)
		return -1;
	
	if (fscanf(file, "%d", &type) != 1)
	{
		fclose(file);
		return -1;
	}

	fclose(file);
	return type;
}

static int read_rapl_config(const char* domain)
{
	char path[256];
	FILE* file;
	int config = -1;
	char buffer[64];

	snprintf(path, sizeof(path), "/sys/bus/event_source/devices/power/events/energy-%s", domain);
	file = fopen(path, "r");
	if (!file)
		return -1;

	// Parse "event=0xXX" format (hexadecimal)
	if (fgets(buffer, sizeof(buffer), file)) {
		if (sscanf(buffer, "event=%i", &config) != 1) {
			// Try parsing as hex if decimal fails
			sscanf(buffer, "event=0x%x", &config);
		}
	}

	fclose(file);
	return config;
}

static void read_rapl_scale()
{
    FILE* file = fopen("/sys/bus/event_source/devices/power/events/energy-pkg.scale", "r");
    if (!file)
	{
        perror("No Scale?");
		return;
	}

    fscanf(file, "%lf", &rapl_scale);
    fclose(file);
}

void rapl_handler__init()
{
	cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
	int rapl_type = read_rapl_type();

	read_rapl_scale();

	if (rapl_type < 0)
		perror("RAPL not available");
	
	for (size_t cpu_idx = 0; cpu_idx < 256; cpu_idx++)
	{
		for (size_t domain_idx = 0; domain_idx < RAPL_MAX_DOMAINS; domain_idx++)
		{
			rapl_file_descriptors[cpu_idx][domain_idx] = -1;
		}
	}

	for (size_t cpu_idx = 0; cpu_idx < cpu_count; cpu_idx++)
	{
		for (size_t domain_idx = 0; domain_idx < RAPL_MAX_DOMAINS; domain_idx++)
		{
			int config = read_rapl_config(rapl_domain_names[domain_idx]);
			if (config < 0)
				continue;
			
			struct perf_event_attr attr = {
				.type           = rapl_type,
				.config         = config,
				.size           = sizeof(struct perf_event_attr),
				.inherit        = 0,
				.disabled       = 0,
				.exclude_kernel = 0,
				.exclude_hv     = 0,
			};

			int fd = perf_event_open(&attr, -1, cpu_idx, -1, 0);
			if (fd < 0)
			{
				perror("Failed to open RAPL");
				continue;
			}

			rapl_file_descriptors[cpu_idx][domain_idx] = fd;
		}
	}
}

double rapl_handler__read_energy_counter(int cpu, int domain)
{
	uint64_t energy = 0;
	fd_t file_descriptor = rapl_file_descriptors[cpu][domain];

	if (file_descriptor < 0)
	{
		//fprintf(stderr, "Failed to find file descriptor for cpu: %d, domain: %d\n", cpu, domain);
		//perror("");
		return 0.0;
	}
	
	if (read(file_descriptor, &energy, sizeof(energy)) != sizeof(energy))
	{
		//perror("Failed to read energy");
		return 0.0;
	}
	
	return (double)energy * rapl_scale;
}

double rapl_handler__read_energy_counter_across_all_cpus(int domain)
{
	double sum = 0.0;

	for (size_t cpu_idx = 0; cpu_idx < cpu_count; cpu_idx++)
	{
		sum += rapl_handler__read_energy_counter(cpu_idx, domain);
	}

	return sum;
}

double rapl_handler__read_energy_counter_across_all_domains(int cpu)
{
	double sum = 0.0;

	for (size_t domain_idx = 0; domain_idx < RAPL_MAX_DOMAINS; domain_idx++)
	{
		sum += rapl_handler__read_energy_counter(cpu, domain_idx);
	}

	return sum;
}

double rapl_handler__read_energy_counter_across_all()
{
	double sum = 0.0;

	for (size_t cpu_idx = 0; cpu_idx < cpu_count; cpu_idx++)
	{
		for (size_t domain_idx = 0; domain_idx < RAPL_MAX_DOMAINS; domain_idx++)
		{
			sum += rapl_handler__read_energy_counter(cpu_idx, domain_idx);
		}
	}

	return sum;
}