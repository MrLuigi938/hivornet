#!/usr/bin/env python3
"""Erzeugt hive/web/world.js: Länderumrisse, ISO-Codes und deutsche Ländernamen.

Quellen (einmalig herunterladen, liegen nicht im Repository):
  curl -sSL -o countries-110m.json https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json
  curl -sSL -o codes.json https://cdn.jsdelivr.net/npm/i18n-iso-countries@7.14.0/codes.json
  curl -sSL -o de.json https://cdn.jsdelivr.net/npm/i18n-iso-countries@7.14.0/langs/de.json

  python3 tools/build_world.py countries-110m.json codes.json de.json hive/web/world.js

Projektion: equirektangulär, x = Länge + 180, y = 90 - Breite (Einheit: Grad).

Datumsgrenze: Länder wie Russland oder Fidschi liegen auf beiden Seiten von
180°. Würde man ihre Punkte einfach umrechnen, zöge ein Ring von x=360 nach x=0
quer über die ganze Karte (waagerechte Streifen). Deshalb werden die Längengrade
jedes Rings "abgewickelt" (keine Sprünge > 180°), und Ringe, die über den
Kartenrand ragen, werden zusätzlich um 360° verschoben gezeichnet. Den Rest
schneidet die viewBox ab.
"""
import json
import sys

# Gebiete ohne ISO-Nummer in world-atlas
EXTRA_CODES = {"Kosovo": "XK", "Somaliland": "SO", "N. Cyprus": "CY"}
SKIP = {"AQ"}  # Antarktis: dort greift niemand an, und sie stört am Kartenrand


def rings_of(topo, geom):
    sx, sy = topo["transform"]["scale"]
    tx, ty = topo["transform"]["translate"]
    arcs = []
    for arc in topo["arcs"]:
        x = y = 0
        pts = []
        for dx, dy in arc:
            x += dx
            y += dy
            pts.append((x * sx + tx, y * sy + ty))
        arcs.append(pts)

    def ring(idx):
        out = []
        for i in idx:
            pts = arcs[i] if i >= 0 else list(reversed(arcs[~i]))
            out.extend(pts if not out else pts[1:])
        return out

    polys = geom["arcs"] if geom["type"] == "MultiPolygon" else [geom["arcs"]]
    for poly in polys:
        for r in poly:
            yield ring(r)


def unwrap(ring):
    """Längengrade ohne Sprünge über die Datumsgrenze."""
    out = []
    prev = None
    for lon, lat in ring:
        if prev is not None:
            while lon - prev > 180:
                lon -= 360
            while lon - prev < -180:
                lon += 360
        out.append((lon, lat))
        prev = lon
    return out


def path(ring, shift):
    seg = []
    last = None
    for lon, lat in ring:
        p = (round(lon + 180 + shift, 1), round(90 - lat, 1))
        if p != last:
            seg.append(p)
            last = p
    if len(seg) < 3:
        return ""
    return "M" + "L".join(f"{x:g} {y:g}" for x, y in seg) + "Z"


def main(topo_path, codes_path, names_path, dst):
    topo = json.load(open(topo_path, encoding="utf-8"))
    num2a2 = {row[2]: row[0] for row in json.load(open(codes_path, encoding="utf-8"))}
    names = {}
    for code, name in json.load(open(names_path, encoding="utf-8"))["countries"].items():
        names[code] = name[0] if isinstance(name, list) else name
    names.setdefault("XK", "Kosovo")

    countries = []
    for g in topo["objects"]["countries"]["geometries"]:
        cc = num2a2.get(str(g.get("id", "")).zfill(3), "") or EXTRA_CODES.get(g["properties"].get("name", ""), "")
        if cc in SKIP:
            continue
        parts = []
        for r in rings_of(topo, g):
            r = unwrap(r)
            if len(r) < 3:
                continue
            xs = [lon + 180 for lon, _ in r]
            parts.append(path(r, 0))
            if min(xs) < 0:
                parts.append(path(r, 360))
            if max(xs) > 360:
                parts.append(path(r, -360))
        d = "".join(p for p in parts if p)
        if d:
            countries.append({"c": cc, "d": d})

    with open(dst, "w", encoding="utf-8", newline="\n") as f:
        f.write("// Erzeugt von tools/build_world.py.\n")
        f.write("// Umrisse: world-atlas countries-110m (ISC-Lizenz, Daten von Natural Earth).\n")
        f.write("// Ländernamen und Codes: i18n-iso-countries (MIT-Lizenz).\n")
        f.write("export const COUNTRIES = " + json.dumps(countries, ensure_ascii=False, separators=(",", ":")) + ";\n")
        f.write("export const COUNTRY_NAMES = " + json.dumps(names, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + ";\n")
    size = sum(len(c["d"]) for c in countries)
    print(f"{dst}: {len(countries)} Länder, {size} Zeichen Umrisse, {len(names)} Namen")


if __name__ == "__main__":
    main(*sys.argv[1:5])
