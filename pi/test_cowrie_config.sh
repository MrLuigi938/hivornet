#!/bin/sh
# Prüft hivornet-cowrie-config (Anmelderegel aus der Web-UI) ohne root und ohne systemd:
# gültige Anfragen werden in cowrie.cfg eingetragen, ungültige abgelehnt.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/bin" "$t/status"
printf '#!/bin/sh\necho "systemctl $*" >>"%s/calls"\n' "$t" >"$t/bin/systemctl"
chmod 755 "$t/bin/systemctl"
cp "$here/rootfs/etc/hivornet/cowrie.cfg" "$t/cowrie.cfg"

run() { # run ANFRAGE
  printf '%s\n' "$1" >"$t/req"
  PATH="$t/bin:$PATH" HIVORNET_COWRIE_REQUEST="$t/req" HIVORNET_COWRIE_CFG="$t/cowrie.cfg" HIVORNET_STATUS_DIR="$t/status" \
    sh "$here/rootfs/usr/local/sbin/hivornet-cowrie-config" >/dev/null 2>&1
}
fail() { echo "FEHLER: $*" >&2; exit 1; }

run "random 3 6" || fail "gültige Anfrage abgelehnt"
grep -qx 'auth_class = AuthRandom' "$t/cowrie.cfg" || fail "AuthRandom fehlt"
grep -qx 'auth_class_parameters = 3, 6, 10' "$t/cowrie.cfg" || fail "Parameter fehlen"
[ "$(grep -c '^auth_class' "$t/cowrie.cfg")" -eq 2 ] || fail "alte Regel nicht ersetzt"
[ "$(head -n 1 "$t/status/cowrie-config")" = ok ] || fail "Status nicht ok"
grep -q "try-restart hivornet-cowrie.service" "$t/calls" || fail "Cowrie nicht neu gestartet"
[ ! -e "$t/req" ] || fail "Anfrage nicht entfernt"

run "userdb" || fail "userdb abgelehnt"
grep -qx 'auth_class = UserDB' "$t/cowrie.cfg" || fail "UserDB fehlt"
if grep -q '^auth_class_parameters' "$t/cowrie.cfg"; then fail "Parameter bei UserDB übrig"; fi

cp "$t/cowrie.cfg" "$t/vorher"
for bad in "random 0 5" "random 6 3" "random 3 99" "rm -rf /" "random 3 6; reboot" ""; do
  if run "$bad"; then fail "ungültige Anfrage angenommen: $bad"; fi
  cmp -s "$t/cowrie.cfg" "$t/vorher" || fail "cowrie.cfg trotz ungültiger Anfrage geändert: $bad"
done
[ "$(head -n 1 "$t/status/cowrie-config")" = failed ] || fail "Status nicht failed"

# Symlink als Anfrage wird nicht gelesen (nur wo echte Symlinks gehen, also nicht unter Git Bash)
ln -s "$t/vorher" "$t/req" 2>/dev/null || true
if [ -L "$t/req" ]; then
PATH="$t/bin:$PATH" HIVORNET_COWRIE_REQUEST="$t/req" HIVORNET_COWRIE_CFG="$t/cowrie.cfg" HIVORNET_STATUS_DIR="$t/status" \
  sh "$here/rootfs/usr/local/sbin/hivornet-cowrie-config" >/dev/null 2>&1 || fail "Symlink: Fehler statt still verwerfen"
cmp -s "$t/cowrie.cfg" "$t/vorher" || fail "Symlink hat cowrie.cfg verändert"
fi
echo "hivornet-cowrie-config: ok"
