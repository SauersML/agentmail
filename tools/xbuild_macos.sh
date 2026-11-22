#!/bin/bash
# Cross-compile mailnode for macOS arm64 (and x86_64 Linux) on a Linux x86_64 box, for when GitHub Actions can't run.
# Uses zig as the linker (cargo-zigbuild) and Apple's macOS SDK for the system frameworks iroh's DNS code links.
# Everything lives under $W (default /root/ambuild): toolchains, SDK, sources (unpacked by the caller into $W/src),
# target dir. Output: $W/out/mailnode-aarch64-apple-darwin, $W/out/mailnode-x86_64-linux, $W/out/SHA256SUMS.
# Run at low priority: nice -n 19 bash xbuild_macos.sh
set -euo pipefail
W=${W:-/root/ambuild}
ZIG_V=0.13.0 SDK_V=14.5
export RUSTUP_HOME=$W/rustup CARGO_HOME=$W/cargo CARGO_TARGET_DIR=$W/target CARGO_BUILD_JOBS=3
export PATH=$CARGO_HOME/bin:$W/zig:$PATH
mkdir -p $W/out
cd $W
log() { echo "$(date -u +%FT%TZ) $*"; }

[ -x $CARGO_HOME/bin/cargo ] || { log rustup; curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path; }
rustup target add aarch64-apple-darwin
[ -x $W/zig/zig ] || { log zig; curl -fsSL https://ziglang.org/download/$ZIG_V/zig-linux-x86_64-$ZIG_V.tar.xz | tar -xJ;
  mv zig-linux-x86_64-$ZIG_V zig; }
command -v cargo-zigbuild > /dev/null || { log cargo-zigbuild; cargo install --locked cargo-zigbuild; }
[ -d $W/sdk/MacOSX$SDK_V.sdk ] || { log sdk; mkdir -p sdk; curl -fsSL \
  https://github.com/joseluisq/macosx-sdks/releases/download/$SDK_V/MacOSX$SDK_V.sdk.tar.xz | tar -xJ -C sdk; }
export SDKROOT=$W/sdk/MacOSX$SDK_V.sdk

cd $W/src
log "build linux"
cargo build --release --locked -p mailnode
cp $CARGO_TARGET_DIR/release/mailnode $W/out/mailnode-x86_64-linux
log "build macos arm64"
cargo zigbuild --release --locked -p mailnode --target aarch64-apple-darwin
cp $CARGO_TARGET_DIR/aarch64-apple-darwin/release/mailnode $W/out/mailnode-aarch64-apple-darwin
cd $W/out && sha256sum mailnode-* > SHA256SUMS && cat SHA256SUMS
log done
