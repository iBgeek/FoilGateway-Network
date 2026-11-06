#!/usr/bin/env bash
# Build the GitHub Releases asset set for FoilGateway Network into versions/<ver>/release/.
# Expects release binaries already in versions/<ver>/ (or dist/).
set -euo pipefail
cd "$(dirname "$0")/.."
VER=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
SRC=${1:-"versions/$VER"}
OUT="$SRC/release"
mkdir -p "$OUT"
need() { [[ -f "$1" ]] || { echo "missing $1" >&2; exit 1; }; }
need "$SRC/foilgw-x86_64"
need "$SRC/foilgw-riscv64"
need "$SRC/foilgw-web.tar.gz"
need "scripts/install.sh"
# Manual: prefer versions/<ver>/, else dist/, else assets build output.
MANUAL=""
for cand in "$SRC/FoilGateway-Manual.html" "dist/FoilGateway-Manual.html" "assets/FoilGateway-Manual.html"; do
  if [[ -f "$cand" ]]; then MANUAL=$cand; break; fi
done
[[ -n "$MANUAL" ]] || { echo "missing FoilGateway-Manual.html" >&2; exit 1; }
cp -f "$SRC/foilgw-x86_64" "$SRC/foilgw-riscv64" "$SRC/foilgw-web.tar.gz" "$OUT/"
cp -f "scripts/install.sh" "$OUT/install.sh"
cp -f "$MANUAL" "$OUT/FoilGateway-Manual.html"
(
  cd "$OUT"
  sha256sum foilgw-x86_64 foilgw-riscv64 foilgw-web.tar.gz install.sh FoilGateway-Manual.html > SHA256SUMS
)
echo "Release assets in $OUT:"
ls -la "$OUT"
echo "---- SHA256SUMS ----"
cat "$OUT/SHA256SUMS"
