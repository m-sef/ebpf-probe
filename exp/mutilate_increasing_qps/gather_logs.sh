#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

LEADER=slmoore@c220g2-011019.wisc.cloudlab.us
MEMCACHED=slmoore@c220g2-011020.wisc.cloudlab.us
AGENT1=slmoore@c220g2-011015.wisc.cloudlab.us
AGENT2=slmoore@c220g2-011016.wisc.cloudlab.us

scp $LEADER:/tmp/leader.log $SCRIPT_DIR/results/
scp $MEMCACHED:/tmp/summary.log $SCRIPT_DIR/results/
scp $AGENT1:/tmp/agent1.log $SCRIPT_DIR/results/
scp $AGENT2:/tmp/agent2.log $SCRIPT_DIR/results/

exit 0