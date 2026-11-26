// Diagramme als SVG: Weltkarte, Zeitverlauf (gestapelte Säulen), Top-Listen.
import { h, s, fmtNum, hoverTip, hideTip, api, flag } from "./dom.js";
import { COUNTRIES, COUNTRY_NAMES } from "./world.js";

export const countryName = (cc) => COUNTRY_NAMES[cc] || (cc === "LAN" ? "Lokales Netz" : cc) || "Unbekannt";

// Farbe folgt dem Dienst, nie dem Rang: jeder Dienst hat seinen festen Platz.
// Verwandte Dienste teilen sich eine Farbe (Fernzugriff, Web, Datenbanken, Mail).
const SVC_COLOR = {
  ssh: "--s1", http: "--s2", https: "--s3", telnet: "--s4", ftp: "--s5", redis: "--s6", mysql: "--s7", dockerapi: "--s8",
  "ssh-tarpit": "--s1", rdp: "--s7", vnc: "--s8", smtp: "--s5", sip: "--s6", snmp: "--s3", dns: "--s2",
  adb: "--s6", mqtt: "--s3", postgres: "--s7", elasticsearch: "--s4", ollama: "--s5", kubernetes: "--s1",
};
const SVC_NAME = {
  ssh: "SSH", telnet: "Telnet", http: "HTTP", https: "HTTPS", ftp: "FTP", redis: "Redis", mysql: "MySQL",
  dockerapi: "Docker-API", "ssh-tarpit": "SSH-Tarpit", raw: "Generisch", other: "Andere",
  smtp: "SMTP", vnc: "VNC", rdp: "RDP", sip: "SIP (UDP)", snmp: "SNMP (UDP)", dns: "DNS (UDP)",
  adb: "ADB", mqtt: "MQTT", postgres: "PostgreSQL", elasticsearch: "Elasticsearch", ollama: "Ollama/KI-API", kubernetes: "Kubernetes",
};
export const svcName = (s) => SVC_NAME[s] || s;
export const svcColor = (s) => `var(${SVC_COLOR[s] || "--other"})`;

// ---------- Weltkarte ----------

// Ausschnitte für die Regionen-Knöpfe (viewBox in Kartenkoordinaten: x = Länge + 180, y = 90 - Breite).
export const REGIONS = {
  Welt: [0, 5, 360, 150], Europa: [160, 22, 78, 32.5], Asien: [235, 28, 110, 46], Nordamerika: [40, 18, 100, 41.7], Südamerika: [80, 85, 72, 30],
};

// worldMap zeichnet die Herkunft der Angriffe.
//   points:    Orte [{lat, lon, n, country, city}]
//   countries: Verbindungen je Land [{key, n}] (sonst aus den Orten summiert)
//   home:      { lat, lon, label } des Honeypots; attack() zieht eine Linie dorthin
//   mode:      "beides" (Länder eingefärbt und Orte), "laender" oder "orte"
//   arcs:      Linien der Angreifer zum Honeypot (track/seedActive):
//              "aktiv" (Standard) wandernde Striche, solange der Angreifer etwas tut (10 Min);
//              "spur"  jede neue Verbindung zeichnet einen Bogen, der einige Minuten hell bleibt
//                      und langsam zu einem ruhigen Bogen verblasst; Angreifer der letzten
//                      15 Minuten bleiben als ruhige Bögen stehen. Höchstens 60 Bögen.
//   arcColor:  (ip) => Farbe eines Bogens (z. B. nach Stufe), sonst var(--attack); recolor(ip) färbt nach
// Zoom mit dem Mausrad, Verschieben durch Ziehen, Doppelklick zeigt die ganze Welt.
// Punkte behalten beim Zoomen ihre Größe auf dem Bildschirm.
export function worldMap(points, { home = null, large = false, countries = null, mode = "beides", controls = true, arcs = "aktiv", arcColor = null } = {}) {
  const spur = arcs === "spur";
  let vb = [...REGIONS.Welt];
  let counts = new Map(), pts = [], max = 1, pmax = 1;
  const k = () => vb[2] / 360;

  // Angriffe je Land heute und insgesamt (für den Tooltip, im Hintergrund geladen)
  const stats = {};
  const midnight = new Date();
  midnight.setHours(0, 0, 0, 0);
  api("stats/countries?today_from=" + midnight.getTime()).then((d) => Object.assign(stats, d)).catch(() => {});
  const countryRows = (cc) => {
    const st = stats[cc] || { today: 0, total: 0 };
    return [["Im Zeitraum", fmtNum(counts.get(cc) || 0)], ["Heute", fmtNum(st.today)], ["Insgesamt", fmtNum(st.total)]];
  };

  const land = s("g", { class: "countries" });
  const paths = new Map();
  for (const c of COUNTRIES) {
    const p = s("path", { class: "country", d: c.d });
    if (c.c) {
      hoverTip(p, () => [[flag(c.c), " ", countryName(c.c)], countryRows(c.c)]);
      paths.set(c.c, [...(paths.get(c.c) || []), p]);
    }
    land.append(p);
  }
  const dots = s("g"), live = s("g"), activeG = s("g", { class: "active-lines" }), homeG = s("g", { class: "home" });
  const lines = new Map(); // IP -> { path, dot, last, open } (Linien gerade aktiver Angreifer)
  const svg = s("svg", { viewBox: vb.join(" "), preserveAspectRatio: "xMidYMid meet", role: "img", "aria-label": "Weltkarte der Angriffsherkunft" }, land, dots, activeG, live, homeG);

  function paint() {
    svg.classList.toggle("mode-orte", mode === "orte"); // Länder reagieren dann nicht auf die Maus
    for (const [cc, ps] of paths) {
      const n = counts.get(cc) || 0;
      const lvl = mode === "orte" || !n ? 0 : Math.min(5, 1 + Math.floor(4.999 * Math.sqrt(n / max)));
      for (const p of ps) p.setAttribute("class", "country k" + lvl);
    }
  }
  function drawDots() {
    dots.replaceChildren();
    if (mode === "laender") return;
    const f = Math.max(k(), 0.12);
    for (const p of [...pts].sort((a, b) => b.n - a.n)) { // kleine Punkte oben
      // Mindestgröße, damit auch einzelne Verbindungen treffbar sind; höchstens 2,1 Grad bei voller Welt
      const r = Math.min(2.1, 0.65 + 1.45 * Math.sqrt(p.n / pmax)) * f;
      const cx = (p.lon + 180).toFixed(2), cy = (90 - p.lat).toFixed(2);
      const c = s("g", { class: "ptg" },
        s("circle", { class: "pt-hit", cx, cy, r: (r + 0.7 * f).toFixed(3) }),
        s("circle", { class: "pt", cx, cy, r: r.toFixed(3), "stroke-width": (0.08 * f).toFixed(3) }));
      hoverTip(c, () => [
        [flag(p.country), " ", [p.city, countryName(p.country)].filter(Boolean).join(", ")],
        [["Verbindungen von hier (Zeitraum)", fmtNum(p.n)], ...(p.country ? countryRows(p.country).slice(1) : [])],
      ]);
      dots.append(c);
    }
  }
  function drawHome() {
    homeG.replaceChildren();
    if (!home || !(home.lat || home.lon)) return;
    const x = home.lon + 180, y = 90 - home.lat;
    homeG.append(s("circle", { class: "home-ring", cx: x, cy: y, r: 2.4 * k(), "stroke-width": 0.3 * k() }), s("circle", { class: "home-dot", cx: x, cy: y, r: 1.1 * k() }));
  }
  hoverTip(homeG, () => [(home && home.label) || "Honeypot", [["Ziel der Angriffe", ""]]]);
  function clamp([x, y, w]) {
    w = Math.min(360, Math.max(12, w));
    const hh = w / 2.4;
    return [Math.min(360 - w, Math.max(0, x)), Math.min(155 - hh, Math.max(5, y)), w, hh];
  }
  function apply() {
    svg.setAttribute("viewBox", vb.map((x) => x.toFixed(3)).join(" "));
    land.style.strokeWidth = (0.2 * k()).toFixed(3);
    drawDots();
    drawHome();
    for (const l of lines.values()) {
      if (spur) l.path.style.strokeWidth = 0.55 * k(); else dashStyle(l.path);
      l.glow.style.strokeWidth = 2.2 * k();
      l.dot.setAttribute("r", 1.1 * k());
    }
  }
  function setView(v, animate = false) {
    const from = [...vb], to = clamp(v);
    if (!animate || matchMedia("(prefers-reduced-motion: reduce)").matches) { vb = to; apply(); return; }
    const t0 = performance.now();
    const step = (t) => {
      const q = Math.min(1, (t - t0) / 350), e = 1 - Math.pow(1 - q, 3);
      vb = from.map((x, i) => x + (to[i] - x) * e);
      apply();
      if (q < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }
  const toMap = (ev) => {
    const r = svg.getBoundingClientRect(), sc = Math.max(vb[2] / r.width, vb[3] / r.height);
    const ox = (r.width - vb[2] / sc) / 2, oy = (r.height - vb[3] / sc) / 2;
    return [vb[0] + (ev.clientX - r.left - ox) * sc, vb[1] + (ev.clientY - r.top - oy) * sc, sc];
  };
  svg.addEventListener("wheel", (ev) => {
    ev.preventDefault();
    const [mx, my] = toMap(ev), w = Math.min(360, Math.max(12, vb[2] * (ev.deltaY > 0 ? 1.25 : 0.8))), q = w / vb[2];
    setView([mx - (mx - vb[0]) * q, my - (my - vb[1]) * q, w]);
  }, { passive: false });
  let drag = null;
  svg.addEventListener("pointerdown", (ev) => { if (ev.button !== 0) return; drag = { x: ev.clientX, y: ev.clientY, vb: [...vb], sc: toMap(ev)[2], moved: false }; });
  svg.addEventListener("pointermove", (ev) => {
    if (!drag) return;
    const dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
    if (!drag.moved && Math.hypot(dx, dy) < 4) return;
    if (!drag.moved) { drag.moved = true; svg.setPointerCapture(ev.pointerId); svg.classList.add("dragging"); hideTip(); }
    setView([drag.vb[0] - dx * drag.sc, drag.vb[1] - dy * drag.sc, drag.vb[2]]);
  });
  const endDrag = () => { drag = null; svg.classList.remove("dragging"); };
  svg.addEventListener("pointerup", endDrag);
  svg.addEventListener("pointercancel", endDrag);
  svg.addEventListener("dblclick", () => setView(REGIONS.Welt, true));

  function setData(points, countries) {
    pts = (points || []).filter((p) => p.lat || p.lon);
    counts = new Map();
    if (countries) for (const c of countries) counts.set(c.key, (counts.get(c.key) || 0) + Number(c.n || 0));
    else for (const p of pts) if (p.country) counts.set(p.country, (counts.get(p.country) || 0) + p.n);
    counts.delete("LAN");
    max = Math.max(1, ...counts.values());
    pmax = Math.max(1, ...pts.map((p) => p.n));
    paint();
    drawDots();
  }
  setData(points, countries);
  apply();

  const box = h("div", { class: "mapbox" }, svg,
    h("div", { class: "scale" }, "wenige ", h("i"), " viele Verbindungen"),
    h("div", { class: "hint" }, "Mausrad: zoomen · Ziehen: verschieben · Doppelklick: Welt"));
  let ctl = null;
  if (controls) {
    const modeSeg = h("div", { class: "seg", role: "group", "aria-label": "Darstellung" });
    for (const [v, l] of [["laender", "Länder"], ["orte", "Orte"], ["beides", "Beides"]]) {
      const b = h("button", { class: v === mode ? "on" : "", onclick: () => {
        mode = v;
        modeSeg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
        paint();
        drawDots();
      } }, l);
      modeSeg.append(b);
    }
    ctl = h("div", { class: "mapctl" },
      h("div", { class: "seg", role: "group", "aria-label": "Ausschnitt" }, Object.keys(REGIONS).map((r) => h("button", { onclick: () => setView(REGIONS[r], true) }, r))),
      modeSeg);
  }
  const el = h("div", { class: "chart map" + (large ? " large" : "") }, box);

  const pulse = (lat, lon, color = "var(--live)") => {
    if (!lat && !lon) return;
    if (live.childNodes.length > 120) live.firstChild.remove();
    const g = s("circle", { class: "pulse", cx: lon + 180, cy: 90 - lat, r: 1.6 * k(), style: { stroke: color, strokeWidth: 0.35 * k() } });
    live.append(g);
    setTimeout(() => g.remove(), 2300);
  };
  // Linie eines aktiven Angreifers: bleibt stehen, solange er etwas tut; verschwindet
  // 20 s nach seiner letzten Verbindung oder nach 2 Minuten ohne jedes Ereignis.
  const arcPath = (x1, y1, x2, y2) => {
    const dist = Math.hypot(x2 - x1, y2 - y1), cx = (x1 + x2) / 2, cy = (y1 + y2) / 2 - Math.min(40, dist * 0.28);
    return `M${x1.toFixed(2)} ${y1.toFixed(2)}Q${cx.toFixed(2)} ${cy.toFixed(2)} ${x2.toFixed(2)} ${y2.toFixed(2)}`;
  };
  // Strichmuster in Karteneinheiten, mit dem Zoom mitskaliert (wandert Richtung Honeypot)
  const dashStyle = (p) => {
    const q = k();
    p.style.strokeWidth = 0.8 * q;
    p.style.strokeDasharray = `${2.4 * q} ${1.3 * q}`;
    let an = p.querySelector("animate");
    if (!an && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
      an = s("animate", { attributeName: "stroke-dashoffset", from: "0", dur: "1.4s", repeatCount: "indefinite" });
      p.append(an);
    }
    if (an) an.setAttribute("to", String(-3.7 * q));
  };
  const dropLine = (ip) => {
    const l = lines.get(ip);
    if (!l) return;
    lines.delete(ip);
    l.g.classList.add("ending");
    setTimeout(() => l.g.remove(), 900);
  };
  // Linie bleibt, bis der Angreifer 10 Minuten (Spur: 15 Minuten) lang nichts mehr getan hat.
  const LINE_MS = (spur ? 15 : 10) * 60e3;
  // Spur: frischer Bogen ist hell und verblasst über TRAIL_MS zu CALM; in den letzten zwei
  // Minuten vor dem Ende geht er ganz aus. Die Helligkeit setzt der Sweep alle 3 s (CSS blendet über).
  const TRAIL_MS = 4 * 60e3, CALM = 0.3, MAX_LINES = 60, FADE_MS = 2 * 60e3;
  const brightness = (l, now) => {
    const age = now - l.fresh, rest = LINE_MS - (now - l.last);
    const o = age < TRAIL_MS ? 1 - (1 - CALM) * (age / TRAIL_MS) : CALM;
    return rest < FADE_MS ? o * Math.max(0, rest / FADE_MS) : o;
  };
  const shade = (l, now = Date.now()) => { if (spur) l.g.style.opacity = brightness(l, now).toFixed(3); };
  const paintLine = (l, ip) => {
    const c = arcColor ? arcColor(ip) : null;
    if (!c) return;
    l.glow.style.stroke = c;
    l.path.style.stroke = c;
    l.dot.style.fill = c;
  };
  // Spur: Bogen vom Ursprung zum Honeypot neu zeichnen (nicht öfter als alle 30 s je Angreifer)
  const redraw = (l) => {
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    l.g.classList.remove("draw");
    void l.g.getBoundingClientRect();
    l.g.classList.add("draw");
  };
  const sweep = setInterval(() => {
    if (!svg.isConnected) { clearInterval(sweep); return; }
    const now = Date.now();
    for (const [ip, l] of lines) if (now - l.last > LINE_MS) dropLine(ip); else shade(l, now);
  }, spur ? 3000 : 5000);
  function addLine(ip, lat, lon, country, city, last, fresh = last) {
    if (!home || !(home.lat || home.lon)) return;
    const x1 = lon + 180, y1 = 90 - lat, x2 = home.lon + 180, y2 = 90 - home.lat;
    if (Math.hypot(x2 - x1, y2 - y1) < 1) return;
    if (spur && lines.size >= MAX_LINES) { // Platz machen: am längsten ruhiger Angreifer geht
      let old = null;
      for (const [k2, l2] of lines) if (!old || l2.last < lines.get(old).last) old = k2;
      dropLine(old);
    }
    const d = arcPath(x1, y1, x2, y2);
    const glow = s("path", { class: "arc-glow", d, style: { strokeWidth: 2.2 * k() } });
    const path = s("path", { class: "arc-live", d, pathLength: spur ? 1 : null });
    if (spur) path.style.strokeWidth = 0.55 * k(); else dashStyle(path);
    const dot = s("circle", { class: "arc-src", cx: x1, cy: y1, r: 1.1 * k() });
    const g = s("g", { class: "active-line" + (spur ? " spur" : "") }, glow, path, dot);
    hoverTip(g, () => [[flag(country), " ", ip], [["Ort", [city, countryName(country)].filter(Boolean).join(", ") || "unbekannt"],
      ["Zuletzt aktiv", new Date(lines.get(ip)?.last || Date.now()).toLocaleTimeString("de-DE")]]]);
    activeG.append(g);
    const l = { g, glow, path, dot, last, fresh, drawn: 0 };
    lines.set(ip, l);
    paintLine(l, ip);
    shade(l);
    if (spur && Date.now() - fresh < 5000) { l.drawn = Date.now(); redraw(l); }
  }
  // Beim Öffnen der Seite: Linien für alle Angriffe der letzten 10 (Spur: 15) Minuten
  function seedActive(attacks) {
    const now = Date.now();
    for (const a of attacks || []) {
      if (now - a.last > LINE_MS || lines.has(a.ip) || (!a.lat && !a.lon)) continue;
      addLine(a.ip, a.lat, a.lon, a.country, a.city, a.last);
    }
  }
  function track(e) {
    if (!e.src_ip) return;
    const l = lines.get(e.src_ip);
    if (e.type === "connect") {
      if (e.country && e.country !== "LAN") {
        counts.set(e.country, (counts.get(e.country) || 0) + 1);
        const st = stats[e.country] || (stats[e.country] = { today: 0, total: 0 });
        st.today++;
        st.total++;
      }
      if (!e.lat && !e.lon) return;
      pulse(e.lat, e.lon, svcColor(e.service));
      const now = Date.now();
      if (l && spur) {
        l.last = l.fresh = now;
        shade(l, now);
        if (now - l.drawn > 30e3) { l.drawn = now; redraw(l); }
        return;
      }
      if (l) { l.last = now; l.g.classList.remove("flash"); void l.g.getBoundingClientRect(); l.g.classList.add("flash"); return; }
      addLine(e.src_ip, e.lat, e.lon, e.country, e.city, now);
      return;
    }
    if (l) l.last = Date.now();
  }
  return {
    el,
    controls: ctl,
    setData,
    track,
    seedActive,
    activeCount: () => lines.size,
    recolor: (ip) => { const l = lines.get(ip); if (l) paintLine(l, ip); },
    zoom: (name) => setView(REGIONS[name], true),
    zoomed: () => vb[2] < 359, // hineingezoomt: Seite nicht automatisch neu aufbauen
    pulse,
    // Angriff: Puls am Ursprung und, wenn ein Standort bekannt ist, eine Linie zum Honeypot.
    attack(lat, lon, service, country) {
      if (country && country !== "LAN") {
        counts.set(country, (counts.get(country) || 0) + 1);
        const st = stats[country] || (stats[country] = { today: 0, total: 0 });
        st.today++;
        st.total++;
      }
      if (!lat && !lon) return;
      pulse(lat, lon, svcColor(service));
      if (!home || !(home.lat || home.lon)) return;
      const x1 = lon + 180, y1 = 90 - lat, x2 = home.lon + 180, y2 = 90 - home.lat;
      const dist = Math.hypot(x2 - x1, y2 - y1);
      if (dist < 1) return;
      // Bogen: Kontrollpunkt über der Mitte, umso höher, je länger die Strecke
      const cx = (x1 + x2) / 2, cy = (y1 + y2) / 2 - Math.min(40, dist * 0.28);
      const arc = s("path", { class: "arc", d: `M${x1.toFixed(2)} ${y1.toFixed(2)}Q${cx.toFixed(2)} ${cy.toFixed(2)} ${x2.toFixed(2)} ${y2.toFixed(2)}`,
        pathLength: 1, style: { stroke: svcColor(service), strokeWidth: 0.45 * k() } });
      live.append(arc);
      setTimeout(() => arc.remove(), 2600);
    },
  };
}

// Verlaufslinie für Kennzahlen
export function sparkline(values, { w = 120, hh = 28 } = {}) {
  const v = values && values.length > 1 ? values : [0, ...(values || [0])];
  const max = Math.max(1, ...v), n = v.length;
  const pts = v.map((x, i) => `${((i / (n - 1)) * w).toFixed(1)},${(hh - 2 - (x / max) * (hh - 4)).toFixed(1)}`).join(" ");
  return s("svg", { class: "spark", viewBox: `0 0 ${w} ${hh}`, preserveAspectRatio: "none", "aria-hidden": "true" },
    s("polyline", { points: `0,${hh} ${pts} ${w},${hh}`, class: "area" }), s("polyline", { points: pts, class: "line" }));
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
  const every = bh === 1 ? 4 : bh === 6 ? 4 : Math.max(5, Math.ceil(buckets.length / 12));
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
