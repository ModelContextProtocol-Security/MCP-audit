#!/usr/bin/env bash
# Run mcp-audit against a hostile surface under a hard deadline, and report
# whether it terminated on its own and what its peak RSS reached.
#
# Surfaces that are expected NOT to terminate are the point: this script exists
# because `vitest` cannot express "assert that this hangs forever" without
# hanging forever.
#
#   ./fixtures/run-hostile.sh infinite-pagination 60
set -uo pipefail
surface="${1:?usage: run-hostile.sh <surface> [deadline-seconds]}"
deadline="${2:-25}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$(mktemp)"

node "$root/dist/cli.js" stdio "node $root/fixtures/hostile-server.mjs $surface" >"$out" 2>&1 &
pid=$!
peak=0
for ((i = 1; i <= deadline * 2; i++)); do
  if ! kill -0 "$pid" 2>/dev/null; then
    wait "$pid"; code=$?
    printf '%-20s terminated after ~%ss, exit=%d, peakRSS=%dMB\n' \
      "$surface" "$(bc <<<"scale=1;$i/2")" "$code" "$peak"
    sed 's/\x1b\[[0-9;]*m//g' "$out"; rm -f "$out"; exit 0
  fi
  rss=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')
  if [[ -n $rss ]]; then mb=$((rss / 1024)); ((mb > peak)) && peak=$mb; fi
  sleep 0.5
done
pkill -P "$pid" 2>/dev/null || true
kill -9 "$pid" 2>/dev/null || true
printf '%-20s *** DID NOT TERMINATE *** killed at %ss, peakRSS=%dMB\n' "$surface" "$deadline" "$peak"
rm -f "$out"
exit 1
