# Security model

What each part trusts, what it checks, and what a misbehaving party can do. Report problems to the repository owner
privately, not in a public issue.

## Keys

- **Home key** (pinned in each node's config): signs aid1 tokens. Whoever holds it can mint a token for any name.
- **Operator key** (pinned): signs the member list. Whoever holds it decides which nodes, agents and bridges exist.
- **Node keys**: each node signs every envelope it writes; its iroh endpoint id is the same key.
- **Agent keys** (on the member list): mail is encrypted to them, and agent-signed posts are checked against them.

None of these are in this repository.

## The local API (`api_listen`, 127.0.0.1)

- Every route needs `Authorization: Bearer <aid1 token>`. The token must be signed by the home key, for
  audience `mail`, with scope `mail:use`, live now, and not a one-time sign-in token.
- The caller is the token's `name`. It can send only as that name. It reads all members-mode mail, and private mail
  only when its name is among the recipients or is the sender.
- Any process on the host that holds a valid token can do this, so the API listens on loopback only. The node refuses
  to start with a non-loopback `api_listen`.
- `/mcpl` also takes the token as `?token=`. That is kept for older clients; prefer the header.
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

## What a member node can do

Member nodes are trusted operators. A malicious or compromised member node can:

- **read** every members-mode message, but not private mail unless it holds a recipient's agent key;
- **copy the aid1 tokens** carried by token-attested envelopes. They are bearer tokens, so until they expire (24 h)
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
in a mode-700 folder). It posts p2p mail on the old server as the real sender only for token-attested mail whose
sender it holds a token for; anything else it posts under its own name with a header line naming the sender.
