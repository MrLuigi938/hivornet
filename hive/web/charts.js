// Diagramme als SVG: Weltkarte, Zeitverlauf (gestapelte Säulen), Top-Listen.
import { h, s, fmtNum, hoverTip } from "./dom.js";
import { LAND } from "./world.js";

// Farbe folgt dem Dienst, nie dem Rang: jeder Dienst hat seinen festen Platz.
// Verwandte Dienste teilen sich eine Farbe (Fernzugriff, Web, Datenbanken, Mail).
const SVC_COLOR = {
  ssh: "--s1", http: "--s2", https: "--s3", telnet: "--s4", ftp: "--s5", redis: "--s6", mysql: "--s7", dockerapi: "--s8",
  "ssh-tarpit": "--s1", rdp: "--s7", vnc: "--s8", smtp: "--s5", sip: "--s6", snmp: "--s3", dns: "--s2",
};
const SVC_NAME = {
  ssh: "SSH", telnet: "Telnet", http: "HTTP", https: "HTTPS", ftp: "FTP", redis: "Redis", mysql: "MySQL",
  dockerapi: "Docker-API", "ssh-tarpit": "SSH-Tarpit", raw: "Generisch", other: "Andere",
  smtp: "SMTP", vnc: "VNC", rdp: "RDP", sip: "SIP (UDP)", snmp: "SNMP (UDP)", dns: "DNS (UDP)",
};
export const svcName = (s) => SVC_NAME[s] || s;
export const svcColor = (s) => `var(${SVC_COLOR[s] || "--other"})`;

// ---------- Weltkarte ----------

// home = { lat, lon, label }: Standort des Honeypots. Ist er gesetzt, zeichnet
// attack() eine Linie vom Ursprung dorthin (Farbe = Dienst).
export function worldMap(points, { home = null, large = false } = {}) {
  const max = Math.max(1, ...points.map((p) => p.n));
  const px = (lon) => lon + 180, py = (lat) => 90 - lat;
  const dots = s("g");
  const sorted = [...points].sort((a, b) => b.n - a.n); // kleine Punkte oben
  for (const p of sorted) {
    const r = 0.8 + 4.2 * Math.sqrt(p.n / max);
    const c = s("circle", { class: "pt", cx: (p.lon + 180).toFixed(2), cy: (90 - p.lat).toFixed(2), r: r.toFixed(2) });
    hoverTip(c, () => [
      [p.city, p.country].filter(Boolean).join(", ") || "Unbekannt",
      [["Verbindungen", fmtNum(p.n)]],
    ]);
    dots.append(c);
  }
  const live = s("g");
  let homeEl = null;
  if (home && (home.lat || home.lon)) {
    const hx = px(home.lon).toFixed(2), hy = py(home.lat).toFixed(2);
    homeEl = s("g", { class: "home" },
      s("circle", { class: "home-ring", cx: hx, cy: hy, r: 2.6 }),
      s("circle", { class: "home-dot", cx: hx, cy: hy, r: 1.3 }));
    hoverTip(homeEl, () => [home.label || "Honeypot", [["Ziel der Angriffe", ""]]]);
  }
  const svg = s("svg", { viewBox: "0 5 360 150", role: "img", "aria-label": "Weltkarte der Angriffsherkunft" },
    s("path", { class: "land", d: LAND }), dots, live, homeEl);
  const el = h("div", { class: "chart map" + (large ? " large" : "") }, svg);
  const pulse = (lat, lon) => {
    if (!lat && !lon) return;
    if (live.childNodes.length > 120) live.firstChild.remove();
    const x = px(lon).toFixed(2), y = py(lat).toFixed(2);
    const g = s("g", null, s("circle", { class: "pulse", cx: x, cy: y, r: 3 }), s("circle", { class: "pulse-core", cx: x, cy: y, r: 1.1 }));
    live.append(g);
    setTimeout(() => g.remove(), 2300);
  };
  return {
    el,
    pulse,
    // Angriff: Puls am Ursprung und, wenn ein Standort bekannt ist, eine Linie zum Honeypot.
    attack(lat, lon, service) {
      if (!lat && !lon) return;
      pulse(lat, lon);
      if (!homeEl) return;
      const x1 = px(lon), y1 = py(lat), x2 = px(home.lon), y2 = py(home.lat);
      const dist = Math.hypot(x2 - x1, y2 - y1);
      if (dist < 1) return;
      // Bogen: Kontrollpunkt über der Mitte, umso höher, je länger die Strecke
      const cx = (x1 + x2) / 2, cy = (y1 + y2) / 2 - Math.min(40, dist * 0.28);
      const d = `M${x1.toFixed(2)} ${y1.toFixed(2)}Q${cx.toFixed(2)} ${cy.toFixed(2)} ${x2.toFixed(2)} ${y2.toFixed(2)}`;
      const arc = s("path", { class: "arc", d, pathLength: 1, style: { stroke: svcColor(service) } });
      const hit = s("circle", { class: "impact", cx: x2.toFixed(2), cy: y2.toFixed(2), r: 2.4, style: { stroke: svcColor(service) } });
      const g = s("g", null, arc, hit);
      live.append(g);
      setTimeout(() => g.remove(), 2600);
    },
  };
}

// ---------- Zeitverlauf ----------

function niceMax(v) {
  if (v <= 4) return 4;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

const wd = ["So", "Mo", "Di", "Mi", "Do", "Fr", "Sa"];

export function timeline(data) {
  const bh = data.bucket_hours;
  const bms = bh * 3600000;
  const first = Math.floor(data.from / bms);
  const last = Math.floor(data.to / bms);
  const buckets = [];
  for (let b = first; b <= last; b++) buckets.push({ t: b * bms, by: {}, total: 0 });
  const totals = {};
  for (const r of data.rows) {
    const idx = Math.floor((r.b * 3600000) / bms) - first;
    if (idx < 0 || idx >= buckets.length) continue;
    buckets[idx].by[r.service] = (buckets[idx].by[r.service] || 0) + r.n;
    buckets[idx].total += r.n;
    totals[r.service] = (totals[r.service] || 0) + r.n;
  }
  // höchstens 5 Dienste einzeln, der Rest als "Andere"
  const ranked = Object.keys(totals).sort((a, b) => totals[b] - totals[a]);
  const shown = ranked.slice(0, 5);
  const series = ranked.length > 5 ? [...shown, "other"] : shown;
  const val = (bk, sv) => (sv === "other" ? Object.entries(bk.by).filter(([k]) => !shown.includes(k)).reduce((a, [, v]) => a + v, 0) : bk.by[sv] || 0);
  const col = (sv) => (sv === "other" ? "var(--other)" : svcColor(sv));

  const W = 720, H = 220, L = 44, R = 8, T = 8, B = 24;
  const pw = W - L - R, ph = H - T - B;
  const ymax = niceMax(Math.max(1, ...buckets.map((b) => b.total)));
  const slot = pw / buckets.length;
  const bw = Math.max(1, Math.min(28, slot * 0.72));
  const y = (v) => T + ph - (v / ymax) * ph;

  const g = s("g");
  for (const tv of [0, ymax / 2, ymax]) {
    g.append(s("line", { class: tv ? "gridline" : "baseline", x1: L, x2: W - R, y1: y(tv), y2: y(tv) }));
    g.append(s("text", { class: "axis-label", x: L - 6, y: y(tv) + 4, "text-anchor": "end" }, fmtNum(tv)));
  }
  const every = bh === 1 ? 4 : bh === 6 ? 4 : 5;
  buckets.forEach((bk, i) => {
    const x = L + i * slot + (slot - bw) / 2;
    let acc = 0;
    for (const sv of series) {
      const v = val(bk, sv);
      if (!v) continue;
      const y0 = y(acc), y1 = y(acc + v);
      g.append(s("rect", { x: x.toFixed(1), y: y1.toFixed(1), width: bw.toFixed(1), height: Math.max(0.5, y0 - y1 - 1).toFixed(1), fill: col(sv), rx: 1 }));
      acc += v;
    }
    if (i % every === 0) {
      const d = new Date(bk.t);
      const label = bh === 1 ? `${String(d.getHours()).padStart(2, "0")}:00`
        : bh === 6 ? `${wd[d.getDay()]} ${d.getDate()}.` : `${d.getDate()}.${d.getMonth() + 1}.`;
      g.append(s("text", { class: "axis-label", x: (L + i * slot + slot / 2).toFixed(1), y: H - 6, "text-anchor": "middle" }, label));
    }
    // Trefferfläche über die ganze Höhe, größer als die Säule
    const hit = s("rect", { x: (L + i * slot).toFixed(1), y: T, width: slot.toFixed(1), height: ph, fill: "transparent" });
    hoverTip(hit, () => {
      const d = new Date(bk.t), e = new Date(bk.t + bms);
      const f = (x) => `${x.getDate()}.${x.getMonth() + 1}. ${String(x.getHours()).padStart(2, "0")}:00`;
      const rows = series.map((sv) => [svcName(sv), fmtNum(val(bk, sv)), col(sv)]).filter((r) => r[1] !== "0");
      rows.push(["Gesamt", fmtNum(bk.total)]);
      return [`${f(d)} – ${f(e)}`, rows];
    });
    g.append(hit);
  });

  const legend = h("div", { class: "legend" },
    series.map((sv) => h("span", null, h("i", { class: "swatch", style: { background: col(sv) } }), svcName(sv))));
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Verbindungen pro Zeitraum nach Dienst" }, g);
  return h("div", { class: "chart" }, series.length > 1 ? legend : null, svg,
    buckets.every((b) => !b.total) ? h("div", { class: "empty" }, "Noch keine Verbindungen in diesem Zeitraum.") : null);
}

// ---------- Top-Liste ----------

export function toplist(rows, { key = (r) => r.key, extra = null, link = null, fmt = fmtNum } = {}) {
  if (!rows || !rows.length) return h("div", { class: "empty" }, "Noch keine Daten.");
  const max = Math.max(...rows.map((r) => r.n));
  return h("ul", { class: "toplist" }, rows.map((r) => {
    const k = key(r);
    const label = link ? h("a", { href: link(r), title: String(k) }, k) : h("span", { title: String(k) }, k);
    return h("li", null,
      h("span", { class: "k" }, label, extra ? [" ", extra(r)] : null),
      h("span", { class: "n" }, fmt(r.n)),
      h("span", { class: "bar" }, h("i", { style: { width: Math.max(1, (100 * r.n) / max) + "%" } })));
  }));
}
