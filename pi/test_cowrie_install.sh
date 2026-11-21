#!/bin/sh
# Testet die Cowrie-Installation des Pi-Images in einem Debian-13-Container (wie
# Raspberry Pi OS "trixie"), ohne systemd:
#
#   docker run --rm -v "$PWD:/src:ro" debian:trixie sh /src/pi/test_cowrie_install.sh
#
# 1. hivornet-cowrie-install läuft durch, der Stand lautet "ok".
# 2. Cowrie startet mit genau dem Befehl und der Umgebung aus hivornet-cowrie.service,
#    als Benutzer ohne Rechte und mit nur lesbarem Quelltext.
# 3. SSH (22) und Telnet (23) antworten, cowrie.json enthält die Verbindungen.
# 4. Eine leere Host-Schlüsseldatei (Stromausfall beim ersten Start) räumt ExecStartPre
#    (hivornet-cowrie-keycheck) weg; Cowrie erzeugt neue Schlüssel und SSH lauscht wieder.
set -eu
SRC=${SRC:-/src}
UNIT="$SRC/pi/rootfs/etc/systemd/system/hivornet-cowrie.service"
fail() { echo "FEHLER: $*" >&2; [ -f /tmp/cowrie.out ] && tail -40 /tmp/cowrie.out >&2; exit 1; }

# Dateien wie im Paket des Images ablegen
mkdir -p /etc/hivornet /usr/local/sbin /usr/local/bin
cp "$SRC/pi/rootfs/etc/hivornet/cowrie.cfg" /etc/hivornet/
cp "$SRC/pi/rootfs/usr/local/sbin/hivornet-cowrie-install" "$SRC/pi/rootfs/usr/local/sbin/hivornet-cowrie-keycheck" /usr/local/sbin/
chmod 755 /usr/local/sbin/hivornet-cowrie-install /usr/local/sbin/hivornet-cowrie-keycheck
# systemctl gibt es im Container nicht: Aufrufe nur mitschreiben
cat >/usr/local/bin/systemctl <<'EOF'
#!/bin/sh
echo "systemctl $*" >>/tmp/systemctl.log
EOF
chmod 755 /usr/local/bin/systemctl

echo "== Installation"
/usr/local/sbin/hivornet-cowrie-install || fail "Installation gescheitert: $(cat /var/lib/hivornet-status/cowrie-install 2>/dev/null)"
[ "$(head -n 1 /var/lib/hivornet-status/cowrie-install)" = ok ] || fail "Stand nicht ok: $(cat /var/lib/hivornet-status/cowrie-install)"
grep -q "enable --now hivornet-cowrie.service" /tmp/systemctl.log || fail "Dienst wurde nicht eingeschaltet"
# Zweiter Lauf: erkennt die fertige Installation
/usr/local/sbin/hivornet-cowrie-install || fail "zweiter Lauf"

echo "== Prüfreihe der Bots (Cowrie-Anpassung)"
# Die Reihe, mit der Bots die Echtheit der Shell prüfen, muss wie in /bin/sh beantwortet werden
# (Rechnen, $$, Subshell, Quoting, /proc/self/stat). Vergleich mit der echten sh dieses Containers.
cp "$SRC/pi/test_cowrie_proc_self.py" "$SRC/pi/test_cowrie_persona.py" "$SRC/pi/test_cowrie_hiveai.py" /tmp/
(cd /opt/hivornet/cowrie && PYTHONPATH=src:/tmp /opt/hivornet/cowrie-env/bin/python3 -m unittest -v test_cowrie_proc_self >/tmp/proc_self.out 2>&1)   || fail "Prüfreihe: $(tail -30 /tmp/proc_self.out)"
echo "== Persona je Angreifer-IP (Cowrie-Anpassung)"
(cd /opt/hivornet/cowrie && PYTHONPATH=src:/tmp /opt/hivornet/cowrie-env/bin/python3 -m unittest -v test_cowrie_persona >/tmp/persona.out 2>&1)   || fail "Persona: $(tail -30 /tmp/persona.out)"
echo "== Modell für Unbekanntes (Cowrie fragt den Hive)"
[ -s /etc/hivornet/cowrie-mimic.token ] || fail "Token für den Hive fehlt"
(cd /opt/hivornet/cowrie && PYTHONPATH=src:/tmp /opt/hivornet/cowrie-env/bin/python3 -m unittest -v test_cowrie_hiveai >/tmp/hiveai.out 2>&1)   || fail "Modell für Unbekanntes: $(tail -30 /tmp/hiveai.out)"

echo "== Start wie hivornet-cowrie.service"
useradd --system --no-create-home --shell /usr/sbin/nologin hivornet-cowrie
# Ordner wie StateDirectory= in der Dienstdatei (systemd legt sie vor dem Start an)
dirs=$(sed -n 's/^StateDirectory=//p' "$UNIT")
for d in tty downloads; do
  case " $dirs " in
    *" hivornet-cowrie/lib/$d "*) ;;
    *) fail "StateDirectory= legt hivornet-cowrie/lib/$d nicht an (Cowrie braucht den Ordner)" ;;
  esac
done
for d in $dirs; do mkdir -p "/var/lib/$d"; done
chown -R hivornet-cowrie /var/lib/hivornet-cowrie
workdir=$(sed -n 's/^WorkingDirectory=//p' "$UNIT")
envs=$(sed -n 's/^Environment=//p' "$UNIT")
pre=$(sed -n 's/^ExecStartPre=//p' "$UNIT")
cmd=$(sed -n 's/^ExecStart=//p' "$UNIT")
if [ -z "$workdir" ] || [ -z "$cmd" ] || [ -z "$pre" ]; then
  fail "WorkingDirectory/ExecStartPre/ExecStart nicht in $UNIT"
fi
cd "$workdir"
# start: wie systemd erst ExecStartPre, dann ExecStart, beides als hivornet-cowrie
start() {
  # shellcheck disable=SC2086 # Umgebung und Befehl bewusst an Leerzeichen trennen (wie systemd)
  runuser -u hivornet-cowrie -- env $envs $pre >>/tmp/keycheck.out 2>&1 || fail "ExecStartPre gescheitert: $(cat /tmp/keycheck.out)"
  # shellcheck disable=SC2086
  runuser -u hivornet-cowrie -- env $envs $cmd >/tmp/cowrie.out 2>&1 &
  pid=$!
}
start

# banner PORT TEXT: wartet bis zu 90 s, bis der Port TEXT sendet
banner() {
  python3 - "$1" "$2" <<'EOF'
import socket, sys, time
port, want = int(sys.argv[1]), sys.argv[2].encode()
end = time.time() + 90
while time.time() < end:
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        data = b""
        while want not in data and len(data) < 4096:
            b = s.recv(1024)
            if not b:
                break
            data += b
        s.close()
        if want in data:
            sys.exit(0)
    except OSError:
        pass
    time.sleep(2)
sys.exit(1)
EOF
}
banner 22 "SSH-2.0-" || fail "SSH auf Port 22 antwortet nicht"
banner 23 "login:" || fail "Telnet auf Port 23 antwortet nicht"
kill -0 "$pid" 2>/dev/null || fail "Cowrie läuft nicht mehr"
if grep -q "Failed to open TTY log" /tmp/cowrie.out; then fail "Cowrie kann keine Mitschnitte schreiben"; fi

log=/var/lib/hivornet-cowrie/log/cowrie.json
for _ in $(seq 1 15); do
  grep -q '"eventid": *"cowrie.session.connect"' "$log" 2>/dev/null && break
  sleep 1
done
grep -q '"eventid": *"cowrie.session.connect"' "$log" 2>/dev/null || fail "$log fehlt oder enthält keine Verbindung"
# Der Hive läuft als anderer Benutzer: "andere" müssen lesen dürfen (644 oder 664)
case "$(stat -c %a "$log")" in
  *[4567]) ;;
  *) fail "$log ist für den Hive nicht lesbar ($(stat -c %a "$log"))" ;;
esac

echo "== Leere Host-Schlüsseldatei"
lib=/var/lib/hivornet-cowrie/lib
ls "$lib"/ssh_host_rsa_key.pub >/dev/null 2>&1 || fail "Cowrie hat keinen RSA-Host-Schlüssel unter $lib angelegt: $(ls "$lib")"
# Cowrie ganz beenden (alle Prozesse des Benutzers) und warten, bis Port 22 frei ist
runuser -u hivornet-cowrie -- sh -c 'kill -TERM -1' 2>/dev/null || true
wait "$pid" 2>/dev/null || true
python3 - <<'EOF2' || fail "Port 22 bleibt nach dem Beenden belegt"
import socket, sys, time
for _ in range(30):
    try:
        socket.create_connection(("127.0.0.1", 22), timeout=2).close()
    except OSError:
        sys.exit(0)
    time.sleep(1)
sys.exit(1)
EOF2
: >"$lib/ssh_host_rsa_key.pub" # wie nach einem Stromausfall beim ersten Start
start
banner 22 "SSH-2.0-" || fail "SSH auf Port 22 antwortet nach leerer Schlüsseldatei nicht"
grep -q "wird entfernt" /tmp/keycheck.out || fail "keycheck hat die leere Datei nicht gemeldet"
[ -s "$lib/ssh_host_rsa_key.pub" ] || fail "RSA-Host-Schlüssel wurde nicht neu erzeugt"
kill "$pid"
echo "Cowrie-Installation: alle Prüfungen bestanden"
