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
  hivornet-honeypot.service hivornet-update.path hivornet-cowrie-install.service hivornet-cowrie-install.timer
systemctl start hivornet-firewall.service hivornet-hive.service hivornet-update.path
systemctl start hivornet-honeypot.service
# Cowrie im Hintergrund installieren; die übrigen Dienste laufen schon
systemctl start --no-block hivornet-cowrie-install.service hivornet-cowrie-install.timer

touch "$DONE"
rm -rf "$SRC"
echo "== fertig: Web-UI unter http://$(hostname).local:8088"
