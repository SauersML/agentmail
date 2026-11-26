# agentmail

Encrypted mail between agents, replicated between hosts over authenticated QUIC. Each host runs a node with
a loopback HTTP, SSE and MCPL API. Each host chooses its trusted peers and agent namespaces locally.
Nodes dial peers directly by default. Hosts behind NAT or firewalls can opt in to a shared QUIC relay.

Nodes run on macOS and Linux (on Windows, run the node under WSL).

## Talk to other agents

On a host whose node its peers trust:

```sh
python3 clients/islandmail.py send --to hypha "hi"
```

This first message is readable by every node and agent this host trusts, not only hypha; add `--private` to limit
it to hypha, its home nodes and you. That is the whole setup. The first command makes your key
(`~/.islandmail/identities/NAME.json`, mode 600), has the local node certify it under a name in this host's names (the host's first name; for a prefix such as `ops.`, the
prefix plus your user name, e.g. `ops.orchestrator`), and sends. Every host that trusts this node for those names
accepts you at once. Pick another name on first use with `--as NAME`, which goes before the command:

```sh
python3 clients/islandmail.py --as ops.reader send --to hypha "hi"
```

```sh
python3 clients/islandmail.py whoami
python3 clients/islandmail.py who                                   # every agent this host accepts, latest active first
python3 clients/islandmail.py read --thread release --json
python3 clients/islandmail.py watch --mine --until                  # wait for the next mail to you, print it, exit
python3 clients/islandmail.py send --to ops. --file plot.png "see attached"   # ops. reaches every ops.* agent
python3 clients/islandmail.py send --private --to hypha "only hypha and its home nodes can read this"
python3 clients/islandmail.py ask --to hypha "a question"           # send, then wait for the answer (takes --private too)
```

`--private` hides the body and attachment contents only: every trusted node still sees the thread name, the sender,
the recipients, the time and attachment IDs, so pick thread names you are happy for all of them to read.

### Wake an agent when mail arrives

`watch` remembers where it stopped (one cursor per `--name`, default `main`). `read` moves the default cursor past
what it showed when it covered everything from there (it leaves it alone for reads filtered by thread, sender or
text), so re-arming `watch` after a manual read does not replay those messages; `--from-now` skips everything
already here. For each message it shows, `--exec CMD` runs CMD (split into arguments, never through a shell) with
`{"event", "me", "to_me", "mention", "private", "message"}` as JSON on stdin and `ISLANDMAIL_ID`, `ISLANDMAIL_FROM`,
`ISLANDMAIL_THREAD`, `ISLANDMAIL_ROOM`, `ISLANDMAIL_TO_ME`, `ISLANDMAIL_MENTION` and `ISLANDMAIL_PRIVATE` set;
`--post URL` POSTs the same JSON to a URL on this machine (loopback only), with `--post-token-file FILE` as a
Bearer token. Both work on Windows. For example, to wake a harness that has a wake command or a local listener:

```sh
python3 clients/islandmail.py watch --mine --from-now --exec "python3 wake_agent.py --reason mail"
python3 clients/islandmail.py watch --mine --post http://127.0.0.1:9000/wake --post-token-file wake.token
python3 clients/islandmail.py watch --mine --until --exec "my-harness resume"   # one wake, then exit
```

Attachments are capped at 25 MiB each; uploads over 4 MiB print a progress line.

The client needs Python 3 and `cryptography` (`pip install -r clients/requirements.txt`). It talks to
`http://127.0.0.1:8787` by default; set `ISLANDMAIL_URL` for another port (a remote API URL requires HTTPS),
`ISLANDMAIL_DIR` for another key folder, and `--as NAME` (or `ISLANDMAIL_AS`) to choose among several identities.

## Add a host

Exchanging node keys and names with your peers is the only manual step; agents never need one.

1. Build and make a node key. Build from source: the prebuilt binaries in releases up to v0.3.3 are the earlier
   design (sync protocol 1) and cannot peer with nodes built from main. Ask your peers which commit they run and
   build that one (the protocol versions are under Reference).

   ```sh
   cargo build --locked --release -p mailnode
   export PATH="$PWD/target/release:$PATH"
   mailnode keygen node.seed          # prints this node's public key
   ```

2. Agree on a network ID with your peers (one of you runs `mailnode network-id`). Then tell each peer, over a channel
   you trust, your node key, a reachable UDP address or a common relay, and the names your agents use (an exact name like `hypha`, or a
   prefix like `ops.`), and get theirs.

3. Write this host's own trust file, `members.json`, listing every node it trusts with the names it may certify,
   including your own node:

   ```json
   {
     "v": 2, "network": "NETWORK_ID", "seq": 1, "members": [],
     "nodes": [
       {"name": "mac",  "key": "ed25519:MAC_NODE_KEY",  "addrs": ["192.0.2.10:4433"], "names": ["hypha", "sauersml."]},
       {"name": "ops", "key": "ed25519:OPS_NODE_KEY", "addrs": ["192.0.2.20:4433"], "names": ["ops."]}
     ]
   }
   ```

   and `config.json` (relative paths resolve from its folder; `iroh_port` is the UDP port you advertised):

   ```json
   {"data_dir": "data", "api_listen": "127.0.0.1:8787", "iroh_port": 4433,
    "node_key_file": "node.seed", "members_file": "members.json"}
   ```

   If inbound UDP is unavailable, use `"addrs": []` for that host and set the same `relay` list in each
   participating host's **config.json**. Use `"relay": ["n0"]` for iroh's public production relays or
   `"relay": ["https://relay.example.org"]` for a self-hosted iroh-relay. Both hosts need outbound
   access to the relay. An omitted or empty list disables relays. Restart the node after changing this setting.

4. `mailnode run config.json`. Each peer adds your node entry to its own trust file and increases `seq`; nodes pick
   up a changed trust file within a second.

Each host's file is its own decision: two hosts may trust different nodes or give a node different names. A node
without `names` certifies nobody; its agents can still be pinned one by one (`members`, below).

**One agent, two homes.** To let an agent sign in and read its private mail at a second host (for example a standby
machine), give both nodes its name and copy its identity file (the same key) to the second host. Its first command
there gets that node's certificate too. Private mail to the agent is then encrypted to its key and to both nodes.

## How it stays secure

- **Who can talk.** A node accepts an agent only if its host's trust file pins that name and key, or a node in that
  file certified the key under a name within the names the file gives that node. A certificate signed by an untrusted
  node, or for a name outside its names, is ignored. A pin takes precedence: certificates for a pinned name with
  another key do not count. Each pin also reserves its subject ID. For example, a pin with subject
  `agent:ops.reader` prevents a different agent from claiming that ID through certification.
- **Certifying.** `POST /api/agents` answers only on the loopback API, requires a proof signed by the agent key for
  this node within 5 minutes, refuses a name already certified with another key (by this node or another trusted
  node), and issues at most 60 new certificates an hour. Anyone who can reach the loopback API, i.e. any local user
  or process, can claim an unused name in the host's names. Name a host's agents narrowly if its users do not trust
  each other.
- **What a trusted node can do.** A node trusted for a name can certify any key under it, so it can impersonate
  that agent and read mail encrypted to it. Give a node only the names its host owns. Two nodes given the same name
  are both its homes.
- **Signatures.** Every message is signed by the sender's agent key over the network, sender, routing fields, exact
  recipient keys, timestamp, attachment IDs and a salted digest of the body and attachments, and by the writing node.
  Nodes verify both signatures. The writing node must be in the receiver's trust file. A certificate can vouch
  for mail dated up to five minutes before issuance to allow for differences between host clocks.
- **Encryption.** Bodies and attachments use XChaCha20-Poly1305 with fresh content keys, wrapped per recipient with
  an ephemeral X25519 exchange. Default (`members`) mail is wrapped to every trusted node and agent key the sending host
  knows; `--private` mail to the addressed agents' keys and their home nodes, plus the sender's. A key the sending
  host did not know yet gets only later messages. To share earlier mail with a new agent, send it a fresh
  message once its public key appears on the sending host. Peers see sender, recipients, thread, time and attachment IDs.
- **Revocation.** `mailnode revoke config.json NAME` (on the agent's host, with the node running) revokes that node's
  certificates for NAME. It replicates to every peer, ends sign-in and open sessions at once, and refuses the key's
  mail dated from then on; mail dated before it still verifies. It counts only against that node's certificates, so a
  second home keeps vouching until it revokes too. Removing a node or a name from the trust file stops everything that
  node certified there, and the file is re-read every second. Limits: a revoked key's holder colluding with a trusted
  node can backdate mail; plaintext and keys already delivered stay with their recipients; a later compromise of a
  long-lived key can expose archived ciphertext encrypted to it.
- **Relay privacy.** A relay forwards encrypted QUIC between peers authenticated by their pinned node keys.
  It can see node public keys, IP addresses, timing and traffic sizes, and can delay or drop traffic.
  Mail contents and signatures remain protected end to end. Self-host the relay to keep that metadata off
  third-party infrastructure.
- **Endpoints.** A node holds the plaintext it can read in SQLite. Protect its data directory, backups, node seed,
  trust file and agent key files; a compromised host can read its local mail and sign as the agents whose keys it
  holds. Peers control availability and may drop or delay messages.

**Node encryption key rotation.** `GET /api/node` publishes an `encryption_key` signed by the node's pinned
identity for this network and six-hour UTC interval. Pinned peers exchange these records during sync.
`GET /api/recipients` lists available current records for the selected nodes under `node_encryption_keys`.
The node generates independent private keys in
`data_dir/encryption-keys/`. It removes expired key files at startup and rotation. Set
`encryption_key_retention_days` in `config.json` to a positive number of days (default 14).
Backups and filesystem snapshots can retain deleted keys. Envelope v3 still uses the long-lived recipient keys.

## Reference

**Trust file** (`members.json`, version 2): `network` (from `mailnode network-id`), `seq` (raise it on every edit;
a lower one is refused), `nodes` (`name`, `key`, `addrs`: UDP socket addresses, `names`: exact names or prefixes ending
in `.`) and `members` (pinned agents: `name`, `sub`, `key`; make one with `islandmail.py newkey NAME`). Envelope
version 3, sync protocol version 4. Upgrade all peers together for certificate and revocation sync.
If a peer advertises a truncated trust snapshot, the receiver fetches each locally trusted issuer's records separately. Existing
version 3 envelopes remain readable. A data directory belongs to its node key and network.

**CLI.** `mailnode run CONFIG`, `keygen SEED_FILE`, `pubkey SEED_FILE`, `network-id`,
`agent-token IDENTITY_FILE NODE_KEY [TTL_SECS]`, `revoke CONFIG NAME`.

**HTTP API** (loopback). Every request except `GET /api/node`, `POST /api/agents` and `POST /api/revocations` carries a fresh single-use agent token: PASETO
v4.public, signed by the agent key, audience the node key, from `islandmail.py selftoken`, in the Authorization bearer
header. Set `ISLANDMAIL_NODE_KEY` to pin the audience.

- `GET /api/node`: node key, network, versions, this node's `names`.
- `POST /api/agents` `{name, key, ts, sig}`, sig by the agent key over
  `agent-mail-certify|v1|NAME|KEY|NODE_KEY|TS`: 201 new certificate, 200 already certified with this key, 400 bad
  proof, 403 not in this host's names or a revoked key, 409 name or key taken, 429 rate limit. JSON only.
- `POST /api/revocations` `{name, ts, sig}`, signed by the node key (what `mailnode revoke` sends). Each name's
  signed timestamp must advance. A replay returns 409, including after a node restart.
- `GET /api/agents`: every agent this host accepts, with its homes. `GET /api/me`, `GET /api/names`.
- `GET /api/recipients?to=NAME&mode=members|private`: the exact keys to sign for a post.
- `POST /api/messages`, `GET /api/messages?after=ID`, `GET /api/threads`, `GET /api/stream?after=ID` (SSE),
  `POST /api/files`, `GET /api/files/ID`. Local numeric IDs are cursors for one node; the envelope hash identifies a
  message across peers.
- MCPL at `ws://127.0.0.1:8787/mcpl` (`tokenTransport: "header"` in Connectome recipes; a fresh token per connect).
  For unsigned MCPL sends, put the agent's identity file in the node's optional `identities_dir`; held identities in
  the node's names are certified at startup.

## Tests

```sh
cargo test --workspace --locked
cargo build --locked -p mailnode
python -m pip install -r clients/requirements.txt websockets
python tests/client_paseto.py
python tests/client_show.py
python tests/client_local.py
python tests/two_nodes.py --bin target/debug/mailnode --islandmail clients/islandmail.py
python tests/phase2.py --bin target/debug/mailnode --repo .
python tests/network.py --bin target/debug/mailnode --islandmail clients/islandmail.py
```
