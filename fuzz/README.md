# Fuzzing and protocol property tests

`fuzz/` is its own workspace (its own `Cargo.lock`), so the node's build never depends on it. `harness/` compiles
the `islandmail-node` modules as a library (the node itself is a binary) and holds a fixed world: seeds, a trust
file, nodes on temporary stores.

Each target is one parser of untrusted bytes, fed raw and, where a signature would stop the fuzzer early, also
signed by the key it names so the layout behind the signature gets fuzzed:

| target | input |
|---|---|
| envelope | an envelope's wire JSON (gossip, sync `get`), through check, open and verify |
| sealed_body | the sealed header and body after decryption (padded or not), through unpad, verify_opened and ingest |
| crypto_open | ciphertext, ephemeral key, wrap slots, padding and blobs |
| cert | certificates and revocations (gossip, sync `certs`) |
| trust_file | the trust file and what is derived from it |
| paseto, agent_token | PASETO v4.public tokens and agent tokens (the API's bearer token) |
| aid1, node_key | home identity tokens and proofs; peers' announced encryption keys and home entries |
| codecs | base64url, base58, base32 ids and prefixes, timestamps, keys, names |
| room | room meta and event folding |
| invite | compact `im1` invites and `imr1` replies |
| join_handshake | ALPN `islandmail/join/1`: any bytes from any key, and signed replies against a live invite |
| sync_request | ALPN `islandmail/sync/1` requests from a member node |
| gossip | gossiped certificates, revocations and envelopes |
| ingest | validly signed envelopes with fuzzer-chosen headers and bodies |
| api | the loopback HTTP API through the node's router, signed in as a pinned agent |

Run one (nightly Rust, or stable with `RUSTC_BOOTSTRAP=1`; `TMPDIR=/dev/shm` keeps the test stores off the disk):

    cargo install cargo-fuzz
    cd fuzz && cargo fuzz run envelope -- -max_total_time=600

A crash is fixed with its input as a unit test next to the code it broke. CI (`.github/workflows/fuzz.yml`) runs
every target nightly for a bounded time and uploads crashes and corpora as artifacts.

The property tests (`harness/tests/protocol.rs`) check delivery order, duplicates, replays, interrupted sync,
revocation races, invite nonce races and concurrent trust-file edits on real nodes:

    cargo test --release --manifest-path fuzz/Cargo.toml -p islandmail-fuzz-harness
