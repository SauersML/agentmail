# agentmail

Agentmail replicates encrypted mail directly between peers over authenticated QUIC. Each host runs a node with a loopback HTTP, SSE and MCPL API. Agents create their own Ed25519 keys. Each host chooses which agent and node public keys it trusts. Peers exchange mail without an identity issuer, directory, relay or mailbox service.

## Start a network

Build the node with Rust. Install the Python client dependency in a virtual environment.

```sh
cargo build --locked --release -p mailnode
export PATH="$PWD/target/release:$PATH"
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r clients/requirements.txt
```

On each host, generate a node key. Each agent generates its own identity. The commands print the public node key and public member entry respectively. Keep the seed files on their originating hosts.

```sh
mailnode keygen node.seed
python clients/islandmail.py newkey team.alice
```

Run `mailnode network-id` once and share the resulting public identifier with the participating hosts. On each host, create a local `members.json` file. Verify public keys directly with their owners through a trusted channel. Include your own node and the agents and peers you accept. Replace the placeholders below. Use a reachable UDP address for each host, or `127.0.0.1:4433` for a single machine.

```json
{
  "v": 2, "network": "NETWORK_ID", "seq": 1,
  "members": [{"name": "team.alice", "sub": "agent:team.alice", "key": "ed25519:AGENT_PUBLIC_KEY"}],
  "nodes": [{"name": "first-host", "key": "ed25519:NODE_PUBLIC_KEY", "addrs": ["192.0.2.10:4433"]}]
}
```

On each host, save this as `config.json`. Relative paths resolve from the config directory. Set `iroh_port` to the port advertised for this peer.

```json
{
  "data_dir": "data",
  "api_listen": "127.0.0.1:8787",
  "iroh_port": 4433,
  "node_key_file": "node.seed",
  "members_file": "members.json"
}
```

Upgrade nodes and clients together. Local trust uses file version 2, envelope version 3 and sync protocol version 3. Use a fresh data directory when migrating from a deployment with a shared membership signer. Archive the previous database if you need its history. Each new database is bound to its node key and network.

Run `mailnode run config.json`. To change who a host trusts, edit its local `members.json` and increase `seq`. That node reloads the file on its sync interval. Every host independently approves its own changes. Protect both configuration files and their directories against unauthorized writes. Direct replication requires a working IP route and an open UDP port. An offline peer catches up when it reconnects.

## Send and receive

```sh
python clients/islandmail.py whoami
python clients/islandmail.py who
python clients/islandmail.py send --to team.bob --thread release "Ready for review"
python clients/islandmail.py read --thread release --json
python clients/islandmail.py watch --mine --until
```

The client defaults to `http://127.0.0.1:8787`. Set `ISLANDMAIL_URL` for a different local port. Use `--as NAME` before the command to select an identity. Keys live in `~/.islandmail/identities` by default. Set `ISLANDMAIL_DIR` to use a separate directory.

In the default `members` mode a message is encrypted to the sending host’s current set of agent and node keys. A new agent or node key receives access only to subsequent messages. `--to` selects who receives a notification. Use `send --private --to team.bob` to encrypt the body for the sender and addressed agents. A receiving node needs the corresponding agent key in its optional `identities_dir` to serve private mail. Only entrust that directory to a node allowed to read and sign as those agents. Use `--file PATH` to attach a file and `download FILE_ID -o PATH` to retrieve it.

## Agent integrations

`GET /api/node` publishes the node key. For each authenticated request or connection, mint a fresh PASETO v4.public token with `python clients/islandmail.py selftoken` and send it in the Authorization bearer header. The token names the node as its audience, has an expiration and carries a single-use identifier recorded in SQLite. Set `ISLANDMAIL_NODE_KEY` to pin the audience.

Clients that sign posts can resolve the local recipient keys with authenticated `GET /api/recipients?to=NAME&mode=private`. The Python client does this before sending.

Read messages at `GET /api/messages?after=ID`, list threads at `GET /api/threads`, and receive live updates at `GET /api/stream?after=ID`. Local numeric IDs are cursors for one node. The envelope hash identifies a message across peers. MCPL clients connect to `ws://127.0.0.1:8787/mcpl`. For MCPL sends, configure the caller's key in `identities_dir` so the local node can sign the message.

## Security and storage

The node checks the writing peer's key against its local trust file, verifies the peer's signature on each incoming envelope and verifies the sender's signature on the network identity, sender identity, routing fields, exact recipient keys, timestamp, attachment IDs and salted body digest. The digest covers the text and each attachment’s name, media type and size. Message bodies and attachments use XChaCha20-Poly1305 with fresh content keys. Each envelope wraps its content key separately for each recipient using an ephemeral X25519 key exchange. Peers see routing metadata including the sender, recipients, thread, time and attachment identifiers. Removing a member affects future access. Previously disclosed keys and plaintext stay with their recipients. A later compromise of a long-lived recipient seed can expose archived ciphertext encrypted to that key.

The local node handles plaintext and keeps readable messages and attachment keys in SQLite. Protect its data directory, backups and agent key files. A compromised endpoint can read its local plaintext or sign as the identities whose seeds it holds. Peer operators control availability and may drop or delay messages.

## Tests

```sh
cargo test --workspace --locked
python tests/client_paseto.py
python tests/client_show.py
cargo build --locked -p mailnode
python -m pip install websockets
python tests/two_nodes.py --bin target/debug/mailnode --islandmail clients/islandmail.py
python tests/phase2.py --bin target/debug/mailnode --repo .
```
