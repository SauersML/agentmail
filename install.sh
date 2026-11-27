#!/usr/bin/env bash
# Islandmail installer for macOS and Linux: the node binary and the client into ~/.local/bin, no sudo, no Rust.
#
#   curl -fsSL https://raw.githubusercontent.com/SauersML/islandmail/main/install.sh | bash
#
# Options (curl ... | bash -s -- OPTIONS):
#   --tag TAG   install that release (default: the latest release with node binaries; prereleases count
#               when no full release has them)
#   --from DIR  install from a directory holding the release files (CI's own build); no GitHub lookups
# Re-running upgrades in place. Windows: install.ps1.
set -euo pipefail

REPO=SauersML/islandmail
BIN_DIR="$HOME/.local/bin"
SHARE="$HOME/.local/share/islandmail"

say() { printf '%s\n' "$*"; }
die() { printf 'islandmail install: %s\n' "$*" >&2; exit 1; }

TAG=""
FROM=""
while [ $# -gt 0 ]; do
    case "$1" in
        --tag) [ $# -ge 2 ] || die "--tag needs a value"; TAG="$2"; shift 2 ;;
        --from) [ $# -ge 2 ] || die "--from needs a directory"; FROM="$2"; shift 2 ;;
        -h|--help) sed -n '2,10p' "$0" 2>/dev/null || true; exit 0 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
done

command -v curl >/dev/null || die "curl is required"
CURL=(curl -fsSL --retry 3 --retry-delay 1 --connect-timeout 10)
API=("${CURL[@]}" -H "Accept: application/vnd.github+json")
if [ -n "${GITHUB_TOKEN:-${GH_TOKEN:-}}" ]; then
    API+=(-H "Authorization: Bearer ${GITHUB_TOKEN:-${GH_TOKEN:-}}")
fi

# Platform -> release asset.
os=$(uname -s)
arch=$(uname -m)
case "$os/$arch" in
    Linux/x86_64|Linux/amd64) plat=x86_64-linux ;;
    Linux/aarch64|Linux/arm64) plat=aarch64-linux ;;
    Darwin/arm64) plat=aarch64-macos ;;
    Darwin/x86_64)
        # A shell under Rosetta on Apple silicon reports x86_64; the native binary is the right one.
        if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then plat=aarch64-macos; else plat=x86_64-macos; fi ;;
    MINGW*|MSYS*|CYGWIN*)
        die "on Windows run in PowerShell: irm https://raw.githubusercontent.com/$REPO/main/install.ps1 | iex" ;;
    *) die "no prebuilt binary for $os/$arch; build from source: cargo build --locked --release -p islandmail-node" ;;
esac
NODE_ASSET="islandmail-node-$plat"
FILES=("$NODE_ASSET" islandmail.py requirements.txt SHA256SUMS)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [ -n "$FROM" ]; then
    for f in "${FILES[@]}"; do cp "$FROM/$f" "$tmp/$f" || die "$FROM has no $f"; done
    say "Installing islandmail ($plat) from $FROM"
else
    # The release: --tag, else the latest full release if it has this platform's binary, else the newest release
    # (prereleases included) that does.
    if [ -z "$TAG" ]; then
        urls=$("${API[@]}" --max-time 20 "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
            | grep -o '"browser_download_url": *"[^"]*"' || true)
        if ! printf '%s\n' "$urls" | grep -q "/$NODE_ASSET\"$"; then
            urls=$("${API[@]}" --max-time 20 "https://api.github.com/repos/$REPO/releases?per_page=30" 2>/dev/null \
                | grep -o '"browser_download_url": *"[^"]*"' || true)
        fi
        TAG=$(printf '%s\n' "$urls" | grep "/$NODE_ASSET\"$" | head -n 1 | sed 's#.*/releases/download/\([^/]*\)/.*#\1#' || true)
        [ -n "$TAG" ] || die "found no release with $NODE_ASSET (GitHub API unreachable or rate limited? set GITHUB_TOKEN, or pass --tag)"
    fi
    say "Installing islandmail $TAG ($plat)"
    base="https://github.com/$REPO/releases/download/$TAG"
    dl=()
    for f in "${FILES[@]}"; do dl+=(-o "$tmp/$f" "$base/$f"); done
    "${CURL[@]}" --max-time 300 "${dl[@]}" || die "download from $base failed"
fi

# Every file against SHA256SUMS.
if command -v sha256sum >/dev/null; then sum() { sha256sum "$1" | cut -d' ' -f1; }
else sum() { shasum -a 256 "$1" | cut -d' ' -f1; }; fi
for f in "$NODE_ASSET" islandmail.py requirements.txt; do
    want=$(awk -v n="$f" '$2 == n || $2 == "*" n { print $1; exit }' "$tmp/SHA256SUMS")
    [ -n "$want" ] || die "SHA256SUMS has no line for $f"
    [ "$(sum "$tmp/$f")" = "$want" ] || die "checksum mismatch for $f: refusing to install"
done
say "  checksums match SHA256SUMS"

mkdir -p "$BIN_DIR" "$SHARE"
# Rename over the old binary: a running node keeps its open copy.
cp "$tmp/$NODE_ASSET" "$BIN_DIR/.islandmail-node.new"
chmod 755 "$BIN_DIR/.islandmail-node.new"
mv -f "$BIN_DIR/.islandmail-node.new" "$BIN_DIR/islandmail-node"
cp "$tmp/islandmail.py" "$tmp/requirements.txt" "$SHARE/"

# The client's private Python environment (uv when present: much faster than venv + pip).
venv="$SHARE/venv"
if command -v uv >/dev/null; then
    [ -x "$venv/bin/python" ] || uv venv -q "$venv" >/dev/null 2>&1 || die "uv venv $venv failed"
    uv pip install -q --python "$venv/bin/python" -r "$SHARE/requirements.txt" || die "uv pip install failed"
else
    py=$(command -v python3 || true)
    [ -n "$py" ] || die "the client needs python3 (3.9+) or uv (https://docs.astral.sh/uv/)"
    "$py" -c 'import sys; sys.exit(sys.version_info < (3, 9))' || die "the client needs Python 3.9+; $py is older"
    if [ ! -x "$venv/bin/python" ]; then
        "$py" -m venv "$venv" >/dev/null 2>&1 || { rm -rf "$venv"; die "python3 -m venv failed (on Debian/Ubuntu: apt install python3-venv, or install uv)"; }
    fi
    "$venv/bin/python" -m pip install -q --disable-pip-version-check -r "$SHARE/requirements.txt" || die "pip install failed"
fi

cat > "$BIN_DIR/islandmail" <<EOF
#!/bin/sh
# Islandmail client, installed by install.sh: its own Python environment, and the node binary beside it on PATH.
PATH="$BIN_DIR:\$PATH" exec "$venv/bin/python" "$SHARE/islandmail.py" "\$@"
EOF
chmod 755 "$BIN_DIR/islandmail"

"$BIN_DIR/islandmail-node" --version || die "the installed islandmail-node does not run"
"$BIN_DIR/islandmail" --help >/dev/null || die "the installed islandmail client does not run"

other=$(command -v islandmail-node 2>/dev/null || true)
if [ -n "$other" ] && [ "$other" != "$BIN_DIR/islandmail-node" ]; then
    say "note: $other comes first on PATH; the client uses $BIN_DIR/islandmail-node"
fi

case ":$PATH:" in
    *":$BIN_DIR:"*) run=islandmail ;;
    *)
        case "${SHELL:-}" in
            */zsh) rc="$HOME/.zshrc" ;;
            */bash) if [ "$os" = Darwin ]; then rc="$HOME/.bash_profile"; else rc="$HOME/.bashrc"; fi ;;
            *) rc="$HOME/.profile" ;;
        esac
        if ! grep -qs "$BIN_DIR" "$rc"; then
            printf '\n# Added by the islandmail installer\nexport PATH="%s:$PATH"\n' "$BIN_DIR" >> "$rc"
            say "added $BIN_DIR to PATH in $rc (new shells)"
        fi
        run="$BIN_DIR/islandmail" ;;
esac

say ""
say "Installed islandmail-node and islandmail in $BIN_DIR. Next, with the invite line (im1...) you were sent:"
say ""
say "  $run join im1..."
