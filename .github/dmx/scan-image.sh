#!/usr/bin/env bash
# dmx (github.com/marsch/dmx, P25-04): nothing secret goes into the public image. Scans an image
# (docker save) for secret files and secret-looking values in its layers and its config — .env
# files, private keys, API tokens, 1Password references, dmx/World configuration — before any
# push. Exit 1 with every finding named; exit 0 when clean.
#   .github/dmx/scan-image.sh <image>
set -euo pipefail
img="${1:?image}"
t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
docker save "$img" -o "$t/img.tar"
mkdir -p "$t/x" "$t/fs"; tar -xf "$t/img.tar" -C "$t/x"
# every layer into one tree (later layers win; enough for a scan)
find "$t/x" -type f \( -name '*.tar' -o -name 'layer.tar' \) -o -path '*/blobs/sha256/*' -type f | while read -r l; do
  tar -xf "$l" -C "$t/fs" 2>/dev/null || true
done
found=0
say() { echo "scan-image: $*"; found=1; }
# third-party trees carry test fixtures (keys, fake tokens) of their own — not ours
skip='/(site-packages|dist-packages|node_modules|\.venv/lib|usr/share|usr/lib|\.playwright|\.cache)/'
# 1. files that hold secrets
while read -r f; do say "secret file: ${f#$t/fs}"; done < <(find "$t/fs" -type f \( -name '.env' -o -name '*.env' -o -name 'id_rsa*' -o -name 'id_ed25519*' -o -name '*.pem' -o -name '*.key' -o -name 'credentials*' -o -name 'setup.json' -o -name '.dmx' \) 2>/dev/null | grep -Ev "$skip" || true)
# 2. secret-looking values in our files
pat='(op://[A-Za-z0-9_-]+/|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|dmx-world=|\.unity\.bot|\.dmnet\b)'
while read -r f; do say "secret-looking value in ${f#$t/fs}"; done < <(grep -rIlE "$pat" "$t/fs" 2>/dev/null | grep -Ev "$skip" || true)
# 3. the image config: ENV and labels
docker inspect "$img" --format '{{range .Config.Env}}{{println .}}{{end}}{{range $k,$v := .Config.Labels}}{{$k}}={{$v}}{{println}}{{end}}' >"$t/config"
if grep -iE '(token|secret|password|api_key|apikey)=.+' "$t/config" | grep -vE '=(|none|false|0)$' >"$t/bad" 2>/dev/null && [ -s "$t/bad" ]; then
  while read -r l; do say "secret-looking config: ${l%%=*}=…"; done <"$t/bad"
fi
grep -E "$pat" "$t/config" >/dev/null && say "secret-looking value in the image config"
[ "$found" = 0 ] && echo "scan-image: $img is clean"
exit "$found"
