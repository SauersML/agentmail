#!/bin/bash
# Keeps mailnode running: restarts it 5 s after it exits. Stop with: touch /workspace/agent-mail/STOP (then kill the
# node by the pid in node.pid). Logs: /workspace/agent-mail/logs/{mailnode,supervisor}.log.
A=/workspace/agent-mail
cd $A || exit 1
echo $$ > $A/supervisor.pid
while [ ! -e $A/STOP ]; do
  echo "$(date -u +%FT%TZ) starting mailnode" >> $A/logs/supervisor.log
  RUST_LOG=mailnode=info,iroh=warn,iroh_gossip=warn $A/bin/mailnode run $A/config.json >> $A/logs/mailnode.log 2>&1 &
  echo $! > $A/node.pid
  wait $!
  echo "$(date -u +%FT%TZ) mailnode exited $?" >> $A/logs/supervisor.log
  # Keep the log bounded: rotate at 200 MB.
  if [ "$(stat -c %s $A/logs/mailnode.log 2>/dev/null || echo 0)" -gt 200000000 ]; then
    mv $A/logs/mailnode.log $A/logs/mailnode.log.1
  fi
  sleep 5
done
echo "$(date -u +%FT%TZ) STOP file present; supervisor exits" >> $A/logs/supervisor.log
