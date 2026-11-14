#!/usr/bin/env python3
"""Erzeugt hive/web/world.js aus world-atlas land-110m.json (TopoJSON, ISC-Lizenz).

  curl -sSL -o land-110m.json https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/land-110m.json
  python3 tools/build_world.py land-110m.json hive/web/world.js

Projektion: equirektangulär, x = Länge + 180, y = 90 - Breite (Einheit: Grad).
"""
import json
import sys


def main(src, dst):
    topo = json.load(open(src, encoding="utf-8"))
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

    polys = []
    for geom in topo["objects"]["land"]["geometries"]:
        if geom["type"] == "Polygon":
            polys.append(geom["arcs"])
        elif geom["type"] == "MultiPolygon":
            polys.extend(geom["arcs"])

    parts = []
    for poly in polys:
        for r in poly:
            pts = ring(r)
            if len(pts) < 3 or max(lat for _, lat in pts) < -55:
                continue  # Antarktis weglassen: dort greift niemand an, und sie stört am Kartenrand
            seg = []
            last = None
            for lon, lat in pts:
                p = (round(lon + 180, 1), round(90 - lat, 1))
                if p != last:
                    seg.append(p)
                    last = p
            if len(seg) < 3:
                continue
            parts.append("M" + "L".join(f"{x:g} {y:g}" for x, y in seg) + "Z")
    path = "".join(parts)
    with open(dst, "w", encoding="utf-8") as f:
        f.write("// Erzeugt von tools/build_world.py aus world-atlas land-110m (ISC-Lizenz, Natural Earth)\n")
        f.write("export const LAND = " + json.dumps(path) + ";\n")
    print(f"{dst}: {len(path)} Zeichen, {len(parts)} Flächen")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
