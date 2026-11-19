#!/bin/bash
# Container start command of the relay pod (agent-mail-relay-1). It runs on every pod start, so the relay survives
# restarts without a volume: fetch the official iroh-relay v1.4.1 release (same iroh version as mailnode), check its
# pinned SHA-256, write the config, and keep the relay running under a restart loop. Then hand over to RunPod's
# /start.sh (sshd + keep-alive). Plain HTTP on 3340/tcp: the traffic inside is end-to-end QUIC between node keys.
set -u
mkdir -p /relay/logs
(
  V=v1.4.1
  F=iroh-relay-$V-x86_64-unknown-linux-musl.tar.gz
  SHA=75254641e3fad7fcbac6dee4d485556fbe06ef708340a9d8810469270ba626b8
  until [ -x /relay/iroh-relay ]; do
    if curl -fsSL -o /relay/$F https://github.com/n0-computer/iroh/releases/download/$V/$F \
      && echo "$SHA  /relay/$F" | sha256sum -c - >> /relay/logs/supervisor.log 2>&1; then
      tar -xzf /relay/$F -C /relay && chmod 755 /relay/iroh-relay
    else
      echo "$(date -u +%FT%TZ) download or checksum failed; retrying" >> /relay/logs/supervisor.log
      sleep 15
    fi
  done
  printf 'enable_relay = true\nhttp_bind_addr = "0.0.0.0:3340"\nenable_metrics = false\n' > /relay/relay.toml
  while true; do
    echo "$(date -u +%FT%TZ) starting iroh-relay" >> /relay/logs/supervisor.log
    /relay/iroh-relay --config-path /relay/relay.toml >> /relay/logs/relay.log 2>&1
    echo "$(date -u +%FT%TZ) iroh-relay exited $?" >> /relay/logs/supervisor.log
    sleep 3
  done
) &
exec /start.sh
