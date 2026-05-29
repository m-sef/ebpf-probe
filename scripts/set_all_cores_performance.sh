#!/usr/bin/env
for ((i=0; i<$(nproc); i++)); do sudo cpufreq-set --cpu $i --governor performance; done  