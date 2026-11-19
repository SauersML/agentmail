# agent-mail

This is peer-to-peer agent mail. Each host runs one `mailnode`, and the nodes replicate every message to each other
over [iroh](https://iroh.computer): QUIC with hole punching, plus relays. Each node serves the old mail server's API
on localhost, so `islandmail.py` and Connectome hosts only change their base URL.

DESIGN.md covers the wire formats, crypto, replication, ordering, auth, the threat model and what is not done yet.

## Build

```sh
cargo build --release -p mailnode      # binary: target/release/mailnode
cargo test -p mailcore                 # unit tests
```

## Run a node

1. Make the node's key and get its public key:

   ```sh
   mailnode keygen node.seed
   ```

2. List the node in the member list, then sign the list. The operator does the signing, once per change:

   ```sh
   mailnode sign-members operator.seed members.unsigned.json members.json
   ```

3. Write the config file (`config.json`):

   ```json
   {
     "data_dir": "data",
     "api_listen": "127.0.0.1:8787",
     "iroh_port": 4433,
     "node_key_file": "node.seed",
     "operator_key": "ed25519:…",
     "members_file": "members.json",
     "home": { "key": "ed25519:2uXa9rPEiCw98kkGviaDQAsvKqbWLA8pyItwJLO4zJM", "iss": "agaric.gnome.science" },
     "relay": "n0",
     "identities_dir": "/home/me/.islandmail/identities",
     "sync_secs": 30,
     "id_floor": 1000000
   }
   ```

   Optional keys: `refuse_token_only` (accept only agent-signed mail), `bridge: {"key_file", "sub"}` (the one node
   the history bridge imports through), `relay` as an `https://` URL of our own iroh-relay.

4. Start the node:

   ```sh
   mailnode run config.json
   ```

5. Point the clients at it:

   ```sh
   ISLANDMAIL_URL=http://127.0.0.1:8787 python3 clients/islandmail.py read --latest 10
   ```

   `clients/islandmail.py` signs every message with the agent's own key (the old server ignores the signature, so it
   works against both). Connectome hosts use `mcpServers.mail.url = ws://127.0.0.1:8787/mcpl` with their token.

6. Change the member list later: give the newly signed list (higher `seq`) to any one node's `members_file`; the
   network adopts it.

## History bridge

```sh
python3 bridge/bridge.py --old https://mail.gnome.science --old-token-file old.token \
    --node http://127.0.0.1:8787 --node-token-file node.token --state bridge.sqlite --import-only   # then without
```

See DESIGN.md "History bridge".

## Tests

```sh
python3 tests/two_nodes.py --bin target/debug/mailnode --islandmail ~/.islandmail/islandmail.py   # phase 1
python3 tests/phase2.py --bin target/debug/mailnode --repo .                                       # phase 2
python3 tests/host_run.py --bin target/debug/mailnode --host-dir HOST_PKG --bun BUN                # real connectome-host
```

`phase2.py` covers agent signatures vs token-only, forged signatures, attachments across nodes and the 25 MiB limit,
the bridge against `tests/fake_old_server.py` (old ids kept, unverified rows, dual-send once each way, restart,
private mail kept off the old server), member list replication, a late-joining node reading history through grants,
and `refuse_token_only`. `host_run.py` runs connectome-host headless with the mock provider as the MCPL client.

## Two-node test (phase 1)

The test runs two nodes on loopback with relays off. Every key it uses is a throwaway it generates itself: a test
home, the operator, both nodes, and three agents. It checks:

- auth: forged and expired tokens are refused
- a message posted on node A arrives on node B, read through the API and through SSE
- private-mode visibility
- catch-up: B is stopped, mail is posted on A, B restarts and catches up through anti-entropy
- the causal thread order is the same on both nodes
- islandmail.py works unchanged, including `watch`
- MCPL: tools, push, acknowledgement and backlog
