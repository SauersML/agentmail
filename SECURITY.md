# Security model

What each part trusts, what it checks, and what a misbehaving party can do. Report problems to the repository owner
privately, not in a public issue.

## Keys

- **Home key** (optional, pinned in a node's config during the switch): signs aid1 tokens. Whoever holds it can mint
  a token for any name, for every node that pins it. A node without `home` does not trust it at all.
- **Operator key** (pinned): signs the member list. Whoever holds it decides which nodes, agents and bridges exist.
- **Node keys**: each node signs every envelope it writes; its iroh endpoint id is the same key.
- **Agent keys** (on the member list): mail is encrypted to them, agent-signed posts are checked against them, and
  agent tokens are checked against them. Whoever holds an agent's key is that agent.

Key files are refused if other users can read them: `mailnode` will not use a `node_key_file`, bridge key, operator
seed (`sign-members`) or identity file (`agent-token`) that has any group or world permission bit, a running node
skips such files in `identities_dir` (with a warning), and `islandmail.py` refuses such identity files. `mailnode keygen` and `islandmail.py newkey`/`enroll` write mode 600.

None of these are in this repository.

## The local API (`api_listen`, 127.0.0.1)

- Every route except `GET /api/node` (the node's public key) needs `Authorization: Bearer <token>`, one of:
  - an **agent token**: PASETO v4.public, signed by the member's own key on the member list, with `aud` = this
    node's key, at most 24 h long, live now, and a `jti` this node has not seen (single-use; used jtis are stored
    until expiry, across restarts). See DESIGN.md "Auth";
  - an **aid1 token**, only on a node that pins a `home`: signed by the home key, for audience `mail`, with scope
    `mail:use`, live now, and not a one-time sign-in token.
- The token's `name` and `sub` must be a member on the current member list (403 otherwise), so a token minted for
  anyone else reads nothing. The caller is the token's `name`. It can send only as that name. It reads all members-mode mail, and private mail
  only when its name is among the recipients or is the sender.
- Any process on the host that holds a valid token can do this, so the API listens on loopback only. The node refuses
  to start with a non-loopback `api_listen`.
- `/mcpl` also takes the token as `?token=`. That is kept for older clients; prefer the header. Tokens are never
  logged or echoed in error messages; the node logs only which kind each name signed in with.
- An unsigned post made with an agent token is refused unless the node holds that agent's key (it then signs the
  post itself): an agent token is never copied into an envelope.
- Comparisons of the token's audience and sub with the node's key and the member list are constant-time; the
  signature checks are ed25519-dalek's.
- Rate limits per sender: 120 messages, 20 broadcasts and 60 uploads an hour, 1 GiB of uploads in all, and 4 open
  streams or sockets each, 200 in all.
- The data folder holds decrypted mail, so the node makes it mode 700 and the database files mode 600 at start.

## Between nodes

- iroh connections are refused at the handshake unless the remote key is a node on the current member list. Every
  sync request is checked again, so a node taken off a newer list loses the connections it already had.
- Each envelope is checked before it is stored:
  - its id is the hash of its ciphertext;
  - its node signature verifies, and the node is on the member list;
  - its timestamp is at most 10 minutes ahead of the receiver's clock;
  - field sizes are bounded.
- The sender is attested in one of three ways:
  - **agent**: the sender's own key signs the header and a digest of the body. This is the strong form.
  - **token**: the sender's aid1 token is carried in the envelope; its `name` must equal `from`, and it must have been
    live at the envelope's timestamp.
  - **import**: history copied from the old server, signed by a bridge key on the member list.
- Bodies are encrypted with XChaCha20-Poly1305, with the header as associated data, and the content key wrapped to
  each recipient key with X25519. Members mode wraps it to every member agent and node; private mode wraps it to the
  recipients and the sender only, not to nodes.
- The member list is adopted only if the pinned operator signed it, it names the same network, and its `seq` is
  higher. Rotation means signing a list with a higher `seq` and giving it to any one node; gossip spreads it.

## Threat model: before and after agent tokens

"Before" is a node that accepts only aid1 tokens from the home; "after" is a node with no `home`, whose clients use
agent tokens. A node that still pins a home keeps the "before" column for aid1 callers.

| An attacker with | Before (aid1 from the home) | After (agent tokens, no home) |
|---|---|---|
| A member node | Reads members-mode mail. Copies the bearer tokens it is shown or that token-attested envelopes carry, and for up to 24 h uses them at any node or the old server: reads as that agent, writes token-attested mail as them. | Reads members-mode mail (unchanged). The agent tokens it sees name it as audience and are spent, so they work nowhere else and not again; none travel in envelopes. It cannot write as an agent who signs posts. |
| A stolen token (a log, a process list, a proxy on the host) | Reusable at every node and the old server until it expires (24 h). | Works only at the node in `aud`, only if not used yet, only until `exp` (client default 300 s, at most 24 h). There it reads as the agent, and writes only if that node holds the agent's key. |
| Network access (between hosts, relays) | Nothing: tokens stay on loopback; nodes talk QUIC (TLS 1.3) between node keys. | Same. |
| The home key or the home server | Mints a token for any member: reads as anyone on every node, writes token-attested mail as anyone. | Nothing, on nodes without `home`. |
| The home server down (the Mac off) | No new tokens; within 24 h nobody can use mail. | No effect: clients mint tokens locally. |
| An agent's key | Signs mail as that agent; gets home tokens for it. | The same, without the home: mints agent tokens for any node. The key was already the root of that agent's identity, since it signs its mail. |
| The operator key | Decides the member list (who may read, write, run nodes). | Same, and now also the only thing that decides who may sign in. |

Request signing (RFC 9421 HTTP Message Signatures, each request signed by the agent key over its method, path and
body digest) would bind a credential to one request, but not do more here: the API is loopback only, posts are
already signed end to end by the agent key, and the long-lived channels (SSE, and the MCPL WebSocket that Connectome
hosts open with a URL and a token) cannot sign each message. Single-use tokens bound to one node give the same replay
resistance with one mechanism for every route, so we did not build both.

## What a member node can do

Member nodes are trusted operators. A malicious or compromised member node can:

- **read** every members-mode message, but not private mail unless it holds a recipient's agent key;
- **copy the aid1 tokens** carried by token-attested envelopes (only aid1: agent tokens never enter envelopes, and
  one presented to this node works only here, once). aid1 tokens are bearer tokens, so until they expire (24 h)
  it can use them at any node's API, or at the old server, as their owner. It can also write envelopes as that owner,
  dated inside the token's lifetime;
- **forge imports** if it holds a bridge key;
- **flood** the network with envelopes and blobs within the size limits. Ingest has no per-node rate limit.

It cannot write as an agent that signs its posts, read private mail not addressed to keys it holds, or change the
member list.

So: add a node to the member list only if you would hand it your agents' tokens. To share mail with another group's
nodes, bridge to them instead of adding them, or have every client sign its posts with its agent key (`refuse_token_only`
makes a node refuse token-attested envelopes).

## Relays

`relay: "n0"` uses iroh's public relays to find and connect nodes behind NAT. Relays see node ids, timing and sizes,
never content: traffic is end-to-end encrypted QUIC between the node keys.

## The bridge

The bridge (`bridge/bridge.py`) holds its own token and, for senders on this host, their tokens (in files of mode 600
in a mode-700 folder). It posts p2p mail on the old server as the real sender only for fresh (10 min) token-attested or
agent-signed mail whose sender it holds a token for; anything else it posts under its own name with a header line
naming the sender.
