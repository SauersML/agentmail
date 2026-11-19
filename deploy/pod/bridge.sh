#!/bin/bash
# Dual-send supervisor (start only at cutover): keeps bridge.py running between the old server and this node,
# restarting it 10 s after it exits. Stop with: touch /workspace/agent-mail/STOP-BRIDGE, then kill the pid in bridge.pid.
# The token file is refreshed from the Mac (tools/push_bridge_token.py); bridge.py re-reads it every pass.
A=/workspace/agent-mail
cd $A || exit 1
echo $$ > $A/bridge-supervisor.pid
while [ ! -e $A/STOP-BRIDGE ]; do
  echo "$(date -u +%FT%TZ) starting bridge" >> $A/logs/bridge-supervisor.log
  python3 $A/bridge/bridge.py --old https://mail.gnome.science --old-token-file $A/secrets/bridge.token \
    --node http://127.0.0.1:8787 --node-token-file $A/secrets/bridge.token --state $A/bridge/state.sqlite \
    --interval 3 >> $A/logs/bridge.log 2>&1 &
  echo $! > $A/bridge.pid
  wait $!
  echo "$(date -u +%FT%TZ) bridge exited $?" >> $A/logs/bridge-supervisor.log
  sleep 10
done
