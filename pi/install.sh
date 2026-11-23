#!/bin/sh
# Hivornet-Installation auf dem Raspberry Pi. Läuft genau einmal beim ersten Start,
# als root, angestoßen von cloud-init (user-data "runcmd" und zur Sicherheit auch
# vendor-data). Liegt mit dem Paket auf der Bootpartition (/boot/firmware/hivornet)
# und löscht sich danach dort selbst.
#
# Schritte: Paket entpacken, Systembenutzer anlegen, Token erzeugen, SSH abschalten
# (Port 22 gehört Cowrie), Dienste einschalten und starten. Cowrie selbst installiert
# danach hivornet-cowrie-install.service (braucht Internet, dauert einige Minuten).
# Protokoll: /var/log/hivornet-install.log
set -eu

SRC=/boot/firmware/hivornet
DONE=/var/lib/hivornet-installed
LOG=/var/log/hivornet-install.log

# Nur einmal, auch wenn user-data und vendor-data es beide anstoßen
exec 9>/run/hivornet-install.lock
flock 9
[ -e "$DONE" ] && exit 0
exec >>"$LOG" 2>&1
echo "== Hivornet-Installation $(date -Is)"

[ -f "$SRC/payload.tar.gz" ] || { echo "Paket fehlt in $SRC"; exit 1; }
(cd "$SRC" && sha256sum -c payload.tar.gz.sha256) || { echo "Paket beschädigt (Prüfsumme)"; exit 1; }

tar -xzf "$SRC/payload.tar.gz" -C / --no-same-owner
chmod 755 /opt/hivornet /opt/hivornet/hive /opt/hivornet/honeypot /usr/local/sbin/hivornet-*

systemd-sysusers /usr/lib/sysusers.d/hivornet.conf

# Schutz gegen Hänger: Protokoll auf der Karte, wenig Auslagern, Speichergrenzen der Dienste
# (cgroup-Speicherverwaltung; wirkt nach dem ersten Neustart). Watchdog über system.conf.d.
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal 2>/dev/null || true
sysctl --load /etc/sysctl.d/90-hivornet.conf >/dev/null 2>&1 || true
for c in /boot/firmware/cmdline.txt /boot/cmdline.txt; do
  [ -f "$c" ] || continue
  if ! grep -q 'cgroup_enable=memory' "$c"; then
    cp "$c" "$c.hivornet-alt"
    sed -i '1 s/$/ cgroup_enable=memory cgroup_memory=1/' "$c"
  fi
  break
done
/usr/local/sbin/hivornet-firstboot

# Port 22 übernimmt Cowrie; der echte SSH-Dienst bleibt dauerhaft aus.
systemctl disable --now ssh.service ssh.socket sshswitch.service 2>/dev/null || true
systemctl mask ssh.service ssh.socket 2>/dev/null || true

# Rechnername für http://hivornet.local:8088, sofern niemand einen eigenen gesetzt hat
if [ "$(hostname)" = "raspberrypi" ]; then
  hostnamectl set-hostname hivornet || echo hivornet >/etc/hostname
fi
systemctl restart avahi-daemon.service 2>/dev/null || true

systemctl daemon-reload
systemctl enable hivornet-firstboot.service hivornet-firewall.service hivornet-hive.service \
  hivornet-honeypot.service hivornet-update.path hivornet-cowrie-config.path hivornet-cowrie-install.service hivornet-cowrie-install.timer hivornet-brute-bans.timer hivornet-memstat.timer
systemctl start hivornet-firewall.service hivornet-hive.service hivornet-update.path hivornet-cowrie-config.path hivornet-brute-bans.timer hivornet-memstat.timer
# Einstellung für den Verwaltungsanschluss (USB-Adapter) laden; ein schon verbundener
# Adapter übernimmt sie beim erneuten Verbinden (sonst erst nach dem nächsten Neustart)
if command -v nmcli >/dev/null 2>&1; then
  nmcli general reload conf 2>/dev/null || true
  for dev in /sys/class/net/eth[1-9] /sys/class/net/enx*; do
    [ -e "$dev" ] || continue
    nmcli device connect "${dev##*/}" 2>/dev/null || true
  done
fi
systemctl start hivornet-honeypot.service
# Cowrie im Hintergrund installieren; die übrigen Dienste laufen schon
systemctl start --no-block hivornet-cowrie-install.service hivornet-cowrie-install.timer

touch "$DONE"
rm -rf "$SRC"
echo "== fertig: Web-UI unter http://$(hostname).local:8088"
