/**
 * @file rapl_helpers.hpp
 * @author Seth Moore (slmoore@hamilton.edu)
 * 
 */
#ifndef RAPL_HELPERS_H
#define RAPL_HELPERS_H

#include <unistd.h>
#include <stdio.h>
#include <string.h>

int
read_rapl_type()
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

int
read_rapl_config(
        const char* domain)
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
	if (fgets(buffer, sizeof(buffer), file))
	{
		if (sscanf(buffer, "event=%i", &config) != 1)
		{
			// Try parsing as hex if decimal fails
			sscanf(buffer, "event=0x%x", &config);
		}
	}

	fclose(file);
	return config;
}

int
read_rapl_unit(
		const char* domain,
		char* buffer,
		size_t size)
{
	char path[256];
	FILE* file;

	snprintf(path, sizeof(path), "/sys/bus/event_source/devices/power/events/energy-%s.unit", domain);
	file = fopen(path, "r");
	if (!file)
		return -1;

	if (!fgets(buffer, size, file))
	{
		fclose(file);
		return -1;
	}
	buffer[strcspn(buffer, "\n")] = '\0';
	fclose(file);

	return 0;
}

int
read_rapl_scale(
		const char* domain,
		char* buffer,
		size_t size)
{
	char path[256];
	FILE* file;

	snprintf(path, sizeof(path), "/sys/bus/event_source/devices/power/events/energy-%s.scale", domain);
	file = fopen(path, "r");
	if (!file)
		return -1;

	if (!fgets(buffer, size, file))
	{
		fclose(file);
		return -1;
	}
	buffer[strcspn(buffer, "\n")] = '\0';
	fclose(file);

	return 0;
}

#endif