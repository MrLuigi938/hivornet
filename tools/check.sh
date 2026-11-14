#!/bin/sh
# Prüfungen vor jedem Commit: gofmt, vet, Tests und Cross-Build für beide Module.
#
#   sh tools/check.sh           alles
#   sh tools/check.sh quick     ohne Cross-Build
#
# Braucht Go im PATH (go.mod verlangt 1.26.x; mit GOTOOLCHAIN=auto wird es geladen).
set -eu
cd "$(dirname "$0")/.."
: "${GOTOOLCHAIN:=auto}"
export GOTOOLCHAIN

for mod in hive honeypot; do
  echo "== $mod"
  (
    cd "$mod"
    fmt=$(gofmt -l .)
    [ -z "$fmt" ] || { echo "gofmt: $fmt" >&2; exit 1; }
    go vet ./...
    go test -count=1 ./... >/tmp/hv-test.$$ 2>&1 || { cat /tmp/hv-test.$$; rm -f /tmp/hv-test.$$; exit 1; }
    tail -n 1 /tmp/hv-test.$$
    rm -f /tmp/hv-test.$$
    if [ "${1:-}" != "quick" ]; then
      for arch in amd64 arm64 arm; do
        CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOARM=7 go build -o /dev/null .
        echo "   Build linux/$arch ok"
      done
    fi
  )
done
echo "Alles in Ordnung."
