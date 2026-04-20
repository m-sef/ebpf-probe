#!/usr/bin/env bash

run_experiment() {
    ../power-consumption-logger/power-consumption-logger.py &
    local PID=$!

    sleep 30

    kill -INT "$PID"
}

run_experiment