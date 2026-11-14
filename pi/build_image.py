#!/usr/bin/env python3
"""Baut das Hivornet-Image für den Raspberry Pi.

Nimmt ein offizielles Raspberry Pi OS Lite (trixie) und legt Hivornet auf die
Bootpartition (FAT32): die Programme, die Dateien aus pi/rootfs und den Installer
pi/install.sh. Beim ersten Start installiert cloud-init daraus alles von selbst.
Die Linux-Partition wird nicht angefasst; deshalb braucht der Bau weder Linux noch
Root-Rechte noch Emulation. Läuft unter Windows, macOS und Linux.

Voraussetzung: Python 3.9+ und  pip install pyfatfs==1.1.0

  python3 pi/build_image.py --arch arm64 --version v0.3.0 --bin <ordner mit hive und honeypot>

  --arch arm64   Pi 3, 4, 5, Zero 2 W (empfohlen)
  --arch armv7   32-Bit-System für ältere Modelle
  --base DATEI   bereits geladenes Basis-Image (.img.xz oder .img) statt Download
  --password PW  Passwort für den Konsolen-Benutzer "hivornet" (nur zur Fehlersuche
                 mit Bildschirm und Tastatur). Ohne Angabe ist er gesperrt.
  --out ORDNER   Zielordner (Standard: aktueller Ordner)

Ergebnis: hivornet-pi-<arch>-<version>.img.xz und .sha256 daneben.
"""
import argparse
import hashlib
import io
import lzma
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

# Basis-Images, festgelegt mit Prüfsumme. Bei einem neuen Raspberry Pi OS hier
# eintragen (Adresse und .sha256 stehen im Download-Ordner von raspberrypi.com).
BASE = {
    "arm64": ("https://downloads.raspberrypi.com/raspios_lite_arm64/images/raspios_lite_arm64-2026-10-06/"
              "2026-10-06-raspios-trixie-arm64-lite.img.xz",
              "483db18a48da399b5b7022ffae9a07bc6d99daab30e593aedac09b69ff422843"),
    "armv7": ("https://downloads.raspberrypi.com/raspios_lite_armhf/images/raspios_lite_armhf-2026-10-06/"
              "2026-10-06-raspios-trixie-armhf-lite.img.xz",
              "2c302771f34c67a0b7ae7aa2e0dcdd3eac660504be59193c011ba79d412e1632"),
}

HERE = os.path.dirname(os.path.abspath(__file__))

# Einrichtung beim ersten Start. "runcmd" stößt den Installer an; dieselbe Datei
# steht als vendor-data noch einmal da, falls jemand user-data ersetzt (etwa die
# Anpassungen im Raspberry Pi Imager). Der Installer läuft nur einmal.
USER_DATA = """#cloud-config
# Hivornet: Einrichtung beim ersten Start. Nicht ändern, sonst wird Hivornet
# eventuell nicht installiert. Danach erreichbar unter http://hivornet.local:8088
hostname: hivornet
manage_etc_hosts: true
ssh_pwauth: false
runcmd:
  - [sh, /boot/firmware/hivornet/install.sh]
"""
VENDOR_DATA = """#!/bin/sh
# Hivornet: zweiter Anstoß des Installers (falls user-data ersetzt wurde)
[ -f /boot/firmware/hivornet/install.sh ] && sh /boot/firmware/hivornet/install.sh
exit 0
"""


def log(*a):
    print(*a, flush=True)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def fetch_base(arch, work, base):
    if base:
        return base
    url, want = BASE[arch]
    dst = os.path.join(work, os.path.basename(url))
    log(f"Lade Basis-Image {url}")
    urllib.request.urlretrieve(url, dst)
    got = sha256_file(dst)
    if got != want:
        sys.exit(f"Prüfsumme des Basis-Images stimmt nicht: {got}")
    return dst


def decompress(src, dst):
    opener = lzma.open if src.endswith(".xz") else open
    with opener(src, "rb") as s, open(dst, "wb") as d:
        shutil.copyfileobj(s, d, 16 << 20)


def partitions(img):
    with open(img, "rb") as f:
        mbr = f.read(512)
    if mbr[510:512] != b"\x55\xaa":
        sys.exit("Kein MBR gefunden: ist das ein Raspberry-Pi-Image?")
    out = []
    for i in range(4):
        e = mbr[446 + 16 * i: 462 + 16 * i]
        lba, n = struct.unpack("<II", e[8:16])
        out.append((e[4], lba * 512, n * 512))
    return out


def tar_add(tar, name, data=None, path=None, mode=0o644):
    """Fügt eine Datei mit festem Besitzer root und festen Rechten hinzu."""
    if path is not None:
        with open(path, "rb") as f:
            data = f.read()
    if "\r\n" in (data[:4096].decode("latin-1")) and mode & 0o111 and not name.startswith("opt/"):
        data = data.replace(b"\r\n", b"\n")  # Skripte aus einem Windows-Checkout
    ti = tarfile.TarInfo(name)
    ti.size, ti.mode, ti.uid, ti.gid, ti.mtime = len(data), mode, 0, 0, int(time.time())
    ti.uname = ti.gname = "root"
    tar.addfile(ti, io.BytesIO(data))


def tar_dir(tar, name, mode=0o755):
    ti = tarfile.TarInfo(name)
    ti.type, ti.mode, ti.uid, ti.gid, ti.mtime = tarfile.DIRTYPE, mode, 0, 0, int(time.time())
    tar.addfile(ti)


def build_payload(binaries, version, dst):
    """payload.tar.gz: /opt/hivornet und alles aus pi/rootfs, mit Rechten für Linux."""
    rootfs = os.path.join(HERE, "rootfs")
    with tarfile.open(dst, "w:gz", format=tarfile.GNU_FORMAT) as tar:
        tar_dir(tar, "opt/hivornet")
        for b in ("hive", "honeypot"):
            tar_add(tar, f"opt/hivornet/{b}", path=os.path.join(binaries, b), mode=0o755)
        tar_add(tar, "opt/hivornet/VERSION", data=(version + "\n").encode())
        seen = set()
        for dirpath, dirnames, files in os.walk(rootfs):
            dirnames.sort()
            rel_dir = os.path.relpath(dirpath, rootfs).replace(os.sep, "/")
            for f in sorted(files):
                rel = f if rel_dir == "." else f"{rel_dir}/{f}"
                # Ordner nur anlegen, wenn sie zu Hivornet gehören; Systemordner bleiben, wie sie sind
                parent = os.path.dirname(rel)
                if parent in ("etc/hivornet",) and parent not in seen:
                    tar_dir(tar, parent)
                    seen.add(parent)
                mode = 0o755 if rel.startswith("usr/local/sbin/") else 0o644
                tar_add(tar, rel, path=os.path.join(dirpath, f), mode=mode)


def patch_boot(img, boot_off, boot_size, files):
    """Schreibt Dateien in die FAT32-Bootpartition (über eine Kopie der Partition)."""
    from pyfatfs.PyFatFS import PyFatFS

    part = img + ".boot"
    with open(img, "rb") as f, open(part, "wb") as o:
        f.seek(boot_off)
        o.write(f.read(boot_size))
    fs = PyFatFS(part, read_only=False)
    try:
        if not fs.exists("/cmdline.txt"):
            sys.exit("Bootpartition ohne cmdline.txt: kein Raspberry Pi OS?")
        if not fs.exists("/hivornet"):
            fs.makedir("/hivornet")
        for name, data in files.items():
            with fs.openbin(name, "w") as fh:
                fh.write(data)
    finally:
        fs.close()
    # Gegenprobe: alles wieder lesbar und gleich?
    fs = PyFatFS(part, read_only=True)
    try:
        for name, data in files.items():
            if fs.readbytes(name) != data:
                sys.exit(f"Kontrolle fehlgeschlagen: {name}")
    finally:
        fs.close()
    with open(part, "rb") as p, open(img, "r+b") as f:
        f.seek(boot_off)
        f.write(p.read())
    os.remove(part)


def password_hash(pw):
    if not pw:
        return "*"  # gesperrt: Anmeldung an der Konsole nicht möglich
    try:
        return subprocess.run(["openssl", "passwd", "-6", "-stdin"], input=pw.encode(), check=True,
                              capture_output=True).stdout.decode().strip()
    except (OSError, subprocess.CalledProcessError):
        sys.exit("--password braucht openssl im PATH")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--arch", choices=sorted(BASE), default="arm64")
    ap.add_argument("--version", required=True)
    ap.add_argument("--bin", required=True, help="Ordner mit hive und honeypot (linux/<arch>)")
    ap.add_argument("--base")
    ap.add_argument("--password", default=os.environ.get("PI_PASSWORD", ""))
    ap.add_argument("--out", default=".")
    ap.add_argument("--work", help="Arbeitsordner (Standard: temporär)")
    ap.add_argument("--xz-preset", type=int, default=6)
    a = ap.parse_args()

    for b in ("hive", "honeypot"):
        p = os.path.join(a.bin, b)
        if not os.path.isfile(p):
            sys.exit(f"{p} fehlt")
        with open(p, "rb") as f:
            if f.read(4) != b"\x7fELF":
                sys.exit(f"{p} ist kein Linux-Programm")

    work = a.work or tempfile.mkdtemp(prefix="hivornet-pi-")
    os.makedirs(work, exist_ok=True)
    base = fetch_base(a.arch, work, a.base)
    img = os.path.join(work, "hivornet.img")
    log("Entpacke Basis-Image ...")
    decompress(base, img)

    parts = partitions(img)
    typ, boot_off, boot_size = parts[0]
    if typ not in (0x0B, 0x0C):
        sys.exit(f"Partition 1 ist nicht FAT32 (Typ 0x{typ:02x})")

    payload = os.path.join(work, "payload.tar.gz")
    log("Packe Hivornet ...")
    build_payload(a.bin, a.version, payload)
    with open(payload, "rb") as f:
        pdata = f.read()
    with open(os.path.join(HERE, "install.sh"), "rb") as f:
        installer = f.read().replace(b"\r\n", b"\n")

    files = {
        "/hivornet/payload.tar.gz": pdata,
        "/hivornet/payload.tar.gz.sha256": f"{hashlib.sha256(pdata).hexdigest()}  payload.tar.gz\n".encode(),
        "/hivornet/install.sh": installer,
        "/user-data": USER_DATA.encode(),
        "/vendor-data": VENDOR_DATA.encode(),
        # Erster Benutzer ohne Rückfrage am Bildschirm (Raspberry Pi OS: userconf-pi)
        "/userconf.txt": f"hivornet:{password_hash(a.password)}\n".encode(),
        "/HIVORNET.txt": (
            f"Hivornet {a.version} fuer den Raspberry Pi\r\n\r\n"
            "Karte in den Pi stecken, LAN-Kabel anschliessen, Strom an.\r\n"
            "Nach 2 bis 5 Minuten im Browser oeffnen: http://hivornet.local:8088\r\n"
            "(oder http://<IP-des-Pi>:8088, die IP steht im Router).\r\n\r\n"
            "Beim ersten Aufruf vergibst du dort dein Passwort.\r\n"
            "Protokoll der Installation auf dem Pi: /var/log/hivornet-install.log\r\n").encode(),
    }
    log("Schreibe Bootpartition ...")
    patch_boot(img, boot_off, boot_size, files)

    os.makedirs(a.out, exist_ok=True)
    name = f"hivornet-pi-{a.arch}-{a.version}.img.xz"
    out = os.path.join(a.out, name)
    log(f"Komprimiere nach {out} (dauert einige Minuten) ...")
    comp = lzma.LZMACompressor(format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, preset=a.xz_preset)
    h = hashlib.sha256()
    with open(img, "rb") as s, open(out + ".part", "wb") as d:
        for b in iter(lambda: s.read(8 << 20), b""):
            c = comp.compress(b)
            d.write(c)
            h.update(c)
        c = comp.flush()
        d.write(c)
        h.update(c)
    os.replace(out + ".part", out)
    with open(out + ".sha256", "w", newline="\n") as f:
        f.write(f"{h.hexdigest()}  {name}\n")
    if not a.work:
        shutil.rmtree(work, ignore_errors=True)
    log(f"Fertig: {out} ({os.path.getsize(out) >> 20} MB)")


if __name__ == "__main__":
    main()
