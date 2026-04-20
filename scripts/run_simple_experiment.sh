#!/usr/bin/env bash

NGINX_NODE=slmoore@clnode290.clemson.cloudlab.us
WRK_NODE=slmoore@clnode302.clemson.cloudlab.us
TIMESTAMP=$(date +%Y-%m-%d_%H:%M:%S)

run_experiment() {
	ssh $NGINX_NODE "~/power-consumption-logger/power-consumption-logger.py" &
	ssh $NGINX_NODE "sudo ~/ebpf-probe/build/ebpf_probe enp129s0f0np0 > ebpf-probe.log" &
	ssh $WRK_NODE "~/firm/benchmarks/1-social-network/wrk2/wrk --connections=32 --threads=32 --duration=1m --rate=10000 http://10.10.1.1:80"

	ssh $NGINX_NODE "pkill -INT -f power-consumption-logger"
    ssh $NGINX_NODE "sudo pkill -INT logger"
}

get_remote_logs() {
	mkdir logs/$TIMESTAMP

	scp $NGINX_NODE:~/*.log logs/$TIMESTAMP/
	scp $WRK_NODE:~/*-requests.txt logs/$TIMESTAMP/
}

cleanup_remote_logs() {
	ssh $NGINX_NODE "rm ~/*.log"
	ssh $WRK_NODE "rm ~/*-requests.txt"
}

run_experiment

get_remote_logs

cleanup_remote_logs