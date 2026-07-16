#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
EXPERIMENT_NAME=$1
CONTAINER_NAME=$2

run_workload()
{
    # Load key, value pairs on Memcached server
    sudo docker exec "${CONTAINER_NAME}" taskset -c 0 mutilate -vv --binary -s 10.10.1.1:11211 --loadonly -K fb_key -V fb_value

    # Run mutilate workload
    sudo docker exec "${CONTAINER_NAME}" taskset -c 0 mutilate --binary -s 10.10.1.1:11211 --noload --agent={10.10.1.2,10.10.1.3} --threads=1 --keysize=fb_key --valuesize=fb_value --iadist=fb_ia --update=0.25 --depth=128 --measure_connections=32 --qps=100000 --time=30
}

run_experiment()
{
    LOG_FILE_PATH=$1

    run_workload >> "${LOG_FILE_PATH}"
}

mkdir -p results/

for (( i = 0; i < 10; i++ )); do
    run_experiment "${SCRIPT_DIR}/results/${EXPERIMENT_NAME}-${i}.log"
done

exit 0