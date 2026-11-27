# Fuzzing

`fuzz/` is its own workspace (its own `Cargo.lock`), so the node's build never depends on it. `harness/` compiles
the `islandmail-node` modules as a library and holds a fixed world: seeds, a trust file, nodes on temporary stores.

One target per parser of untrusted bytes:

| target | input |
|---|---|
| envelope | an envelope's wire JSON (gossip, sync `get`), through check, open and verify |
| invite | compact `im1` invites and `imr1` replies |
| paseto | PASETO v4.public tokens (the API's bearer token) |
| sync_request | sync requests from a member node |

Run one (nightly Rust, or stable with `RUSTC_BOOTSTRAP=1`):

    cargo install cargo-fuzz
    cd fuzz && cargo fuzz run envelope -- -max_total_time=600

CI (`.github/workflows/fuzz.yml`) runs every target nightly.
