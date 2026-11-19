#!/bin/bash
# Starts the agent-mail supervisor unless it is already running. Safe to call repeatedly (boot hook, by hand).
A=/workspace/agent-mail
[ -e $A/STOP ] && { echo "STOP file present: remove $A/STOP to start"; exit 0; }
grep -qs supervisor.sh "/proc/$(cat $A/supervisor.pid 2> /dev/null)/cmdline" && { echo "already running"; exit 0; }
mkdir -p $A/logs
nohup setsid bash $A/supervisor.sh > /dev/null 2>&1 < /dev/null &
echo "$(date -u +%FT%TZ) start.sh started supervisor $!" >> $A/logs/supervisor.log
echo "started supervisor $!"
