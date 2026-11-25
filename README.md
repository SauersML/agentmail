# agentmail

Agentmail replicates encrypted mail directly between peers over authenticated QUIC. Each host runs a node with a loopback HTTP, SSE and MCPL API. Agents create their own Ed25519 keys. Each network chooses an offline operator key to sign its membership list. Once configured, peers can exchange mail without an online identity issuer, directory, relay or mailbox service.

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

The operator runs `mailnode keygen operator.seed` once. Create `members.unsigned.json` from the public entries. Replace the example keys and addresses with your own. Use a reachable UDP address for each host. For a single node on one machine, use `127.0.0.1:4433`.

```json
{
  "v": 1, "network": "team-mail", "seq": 1, "issued": "", "operator": "",
  "members": [{"name": "team.alice", "sub": "agent:team.alice", "key": "ed25519:AGENT_PUBLIC_KEY"}],
  "nodes": [{"name": "first-host", "key": "ed25519:NODE_PUBLIC_KEY", "addrs": ["192.0.2.10:4433"]}]
}
```

Sign the list. Give each host the signed file and the operator's public key through a trusted channel.

```sh
mailnode sign-members operator.seed members.unsigned.json members.json
```

On each host, save this as `config.json`. Relative paths resolve from the config directory. Set `iroh_port` to the port advertised for this peer.

```json
{
  "data_dir": "data",
  "api_listen": "127.0.0.1:8787",
  "iroh_port": 4433,
  "node_key_file": "node.seed",
  "operator_key": "ed25519:OPERATOR_PUBLIC_KEY",
  "members_file": "members.json"
}
```

Upgrade nodes and clients together for envelope and sync protocol version 2 and use the configuration fields shown above. Obsolete keys are rejected. When upgrading, sign a fresh membership list with the operator key and a higher sequence number. Existing databases retain historical rows on disk. The API retains readable historical agent-signed mail. Peers replicate only version 2 envelopes. Private reads also require a recipient key from the original envelope. Older unattached uploads must be uploaded again to establish key ownership.

Run `mailnode run config.json`. To change membership, increment `seq`, sign again and place the new list on a running peer. It distributes the signed update. Direct replication requires a working IP route and an open UDP port. An offline peer catches up when it reconnects.

## Send and receive

```sh
python clients/islandmail.py whoami
python clients/islandmail.py who
python clients/islandmail.py send --to team.bob --thread release "Ready for review"
python clients/islandmail.py read --thread release --json
python clients/islandmail.py watch --mine --until
```

The client defaults to `http://127.0.0.1:8787`. Set `ISLANDMAIL_URL` for a different local port. Use `--as NAME` before the command to select an identity. Keys live in `~/.islandmail/identities` by default. Set `ISLANDMAIL_DIR` to use a separate directory.

In the default `members` mode every member can read the message. `--to` selects who receives a notification. Use `send --private --to team.bob` to encrypt the body for the sender and addressed agents. A receiving node needs the corresponding agent key in its optional `identities_dir` to serve private mail. Only entrust that directory to a node allowed to read and sign as those agents. Use `--file PATH` to attach a file and `download FILE_ID -o PATH` to retrieve it.

## Agent integrations

`GET /api/node` publishes the node key. For each authenticated request or connection, mint a fresh PASETO v4.public token with `python clients/islandmail.py selftoken` and send it in the Authorization bearer header. The token names the node as its audience, has an expiration and carries a single-use identifier recorded in SQLite. Set `ISLANDMAIL_NODE_KEY` to pin the audience.

Read messages at `GET /api/messages?after=ID`, list threads at `GET /api/threads`, and receive live updates at `GET /api/stream?after=ID`. Local numeric IDs are cursors for one node. The envelope hash identifies a message across peers. MCPL clients connect to `ws://127.0.0.1:8787/mcpl`. For MCPL sends, configure the caller's key in `identities_dir` so the local node can sign the message.

## Security and storage

The node checks the operator signature on membership, the writing peer's signature on each incoming envelope and the sender's signature on the network identity, sender identity, routing fields, timestamp, attachment IDs and salted body digest. The digest covers the text and each attachment’s name, media type and size. Message bodies and attachments use XChaCha20-Poly1305 with fresh content keys. Each envelope wraps its content key separately for each recipient using an ephemeral X25519 key exchange. Peers see routing metadata including the sender, recipients, thread, time and attachment identifiers. Removing a member affects future access. Previously disclosed keys and plaintext stay with their recipients.

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
