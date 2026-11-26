// Theme „Leitstand“: Lagebild für den Wandmonitor (Entwurf konzepte/themes/1-leitstand.html).
// Einhängepunkte (themes.js): shell (Icon-Leiste, Kopfzeile mit Lage, Live, Uhr, Benutzer),
// onRoute (Titel, Kiosk), dashboard (dichtes Raster ohne Scrollen), cleanup.
// Alle übrigen Seiten bleiben die des Standards und werden nur über skins/leitstand.css angepasst.
import { h, s, mount, api, fmtNum, fmtTime, flag, store, hoverTip, ACTIVE_MS } from "../dom.js";
import { worldMap, sparkline, svcName, countryName } from "../charts.js";
import { STUFE, STUFE_KURZ, sevColor, liveAttacks } from "../attacks.js";
import { state, loadDashboard, describe, TYPE_NAME, warningsBox } from "../app.js";

// ---------- Symbole (Linien, 24er Raster) ----------
const ICON = {
  dash: [["rect", { x: 3.5, y: 3.5, width: 7, height: 7, rx: 1.5 }], ["rect", { x: 13.5, y: 3.5, width: 7, height: 7, rx: 1.5 }], ["rect", { x: 3.5, y: 13.5, width: 7, height: 7, rx: 1.5 }], ["rect", { x: 13.5, y: 13.5, width: 7, height: 7, rx: 1.5 }]],
  attacks: [["circle", { cx: 12, cy: 12, r: 7.5 }], ["circle", { cx: 12, cy: 12, r: 2 }], ["path", { d: "M12 2v5M12 17v5M2 12h5M17 12h5" }]],
  analysis: [["path", { d: "M4 20V10M10 20V4M16 20v-7M21 20H3" }]],
  insights: [["path", { d: "M9 18h6M10 21h4" }], ["path", { d: "M12 3a6 6 0 0 0-3.5 10.9c.6.5 1 1.2 1 2.1h5c0-.9.4-1.6 1-2.1A6 6 0 0 0 12 3z" }]],
  funde: [["path", { d: "M9 3h6M10 3v6l-5.5 9.5A1.5 1.5 0 0 0 5.8 21h12.4a1.5 1.5 0 0 0 1.3-2.5L14 9V3" }], ["path", { d: "M7.5 15h9" }]],
  creds: [["circle", { cx: 8, cy: 15, r: 4 }], ["path", { d: "M11 12l9-9M16 7l3 3M14 9l2 2" }]],
  tarpit: [["path", { d: "M6 3h12M6 21h12M7 3c0 5 5 6 5 9s-5 4-5 9M17 3c0 5-5 6-5 9s5 4 5 9" }]],
  system: [["rect", { x: 6, y: 6, width: 12, height: 12, rx: 2 }], ["rect", { x: 9.5, y: 9.5, width: 5, height: 5 }], ["path", { d: "M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4" }]],
  kiosk: [["path", { d: "M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5" }]],
};
const icon = (k) => s("svg", { viewBox: "0 0 24 24", "aria-hidden": "true", class: "ls-ic" }, (ICON[k] || ICON.dash).map(([t, a]) => s(t, a)));
const ICON_OF = { "#/": "dash", "#/attacks": "attacks", "#/analysis": "analysis", "#/insights": "insights", "#/funde": "funde", "#/creds": "creds", "#/tarpit": "tarpit", "#/system": "system" };

// ---------- Zustand des Rahmens ----------
let R = null; // { app, rail, lage, clock, kioskbar, rot, timers, onKey, onFs, nav }
const lage = { stufe: -1, t: 0 }; // höchste Stufe der Angriffe der letzten 15 Minuten

function renderLage() {
  if (!R) return;
  mount(R.lage, lage.stufe >= 0
    ? [h("span", { class: "muted" }, "Lage (15 Min)"), h("b", { style: { "--c": sevColor(lage.stufe) }, title: STUFE[lage.stufe] }, `STUFE ${lage.stufe} · ${STUFE[lage.stufe]}`)]
    : lage.t ? [h("span", { class: "muted" }, "Lage (15 Min)"), h("b", { class: "ruhig" }, "RUHIG")] : null);
}
function setLage(attacks) {
  const now = Date.now();
  lage.stufe = (attacks || []).filter((a) => !a.own && now - a.last < ACTIVE_MS).reduce((m, a) => Math.max(m, a.stufe), -1);
  lage.t = now;
  renderLage();
}
async function pollLage() {
  if (document.hidden || location.hash.replace(/^#\/?/, "") === "") return; // die Übersicht pflegt die Lage selbst
  const d = await api("attacks?active=1&limit=60", { noAuthRedirect: true }).catch(() => null);
  if (d) setLage(d.attacks);
}

// ---------- Kiosk: Vollbild ohne Leiste, Seiten wechseln alle 25 s ----------
function kiosk(on) {
  if (!R) return;
  document.documentElement.classList.toggle("ls-kiosk", on);
  R.kioskbar.hidden = !on;
  clearInterval(R.rotTimer);
  if (on) {
    try { document.documentElement.requestFullscreen?.().catch(() => {}); } catch { /* Vollbild nicht erlaubt: Kiosk im Fenster */ }
    R.rotTimer = setInterval(() => {
      if (!R.rot.checked || document.hidden) return;
      location.hash = /^#\/attacks/.test(location.hash) ? "#/" : "#/attacks";
    }, 25000);
  } else if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
}
const kioskOn = () => document.documentElement.classList.contains("ls-kiosk");

// ---------- Einhängepunkt: Rahmen ----------
export function shell(app, teile) {
  cleanup();
  const rail = h("nav", { class: "ls-rail", "aria-label": "Hauptnavigation" },
    h("a", { class: "ls-logo", href: "#/", "aria-label": "Hivornet" }, h("img", { src: "favicon.svg", alt: "" })),
    teile.nav.map(([href, label], i) => h("a", { href, "data-navlink": "", "data-l": `${label}  (${i + 1})`, "aria-label": label, title: "" }, icon(ICON_OF[href]))),
    h("span", { class: "sp" }),
    h("button", { class: "ls-ic-btn", type: "button", "data-l": "Kiosk-Modus (K)", "aria-label": "Kiosk-Modus", onclick: () => kiosk(true) }, icon("kiosk")));
  const top = h("div", { class: "top" });
  const main = h("div", { class: "ls-view" });
  const lageEl = h("div", { class: "ls-lage", role: "status" });
  const clock = h("div", { class: "ls-clock num" });
  const rot = h("input", { type: "checkbox", checked: store("lsRotate") !== "0", onchange: (e) => store("lsRotate", e.target.checked ? "1" : "0") });
  const kioskbar = h("div", { class: "ls-kioskbar", hidden: true },
    h("label", { class: "inline" }, rot, " Seiten wechseln"),
    h("button", { class: "btn small", type: "button", onclick: () => kiosk(false) }, "Kiosk beenden (Esc)"));
  const root = h("div", { class: "ls-app" }, rail,
    h("div", { class: "ls-stage" },
      h("header", { class: "ls-bar" }, top, lageEl, teile.live, clock, teile.userMenu),
      h("main", { class: "ls-main" }, main, teile.credit)),
    kioskbar);
  mount(app, root);

  const tick = () => { clock.textContent = new Date().toLocaleTimeString("de-DE"); };
  tick();
  const onKey = (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey || e.target.closest?.("input, textarea, select, [contenteditable]")) return;
    if (e.key === "Escape" && kioskOn()) kiosk(false);
    else if (e.key === "k" || e.key === "K") kiosk(!kioskOn());
    else if (/^[1-8]$/.test(e.key) && teile.nav[Number(e.key) - 1]) location.hash = teile.nav[Number(e.key) - 1][0];
  };
  const onFs = () => { if (!document.fullscreenElement && kioskOn()) kiosk(false); };
  document.addEventListener("keydown", onKey);
  document.addEventListener("fullscreenchange", onFs);
  R = { app: root, rail, lage: lageEl, clock, kioskbar, rot, onKey, onFs, rotTimer: null,
    timers: [setInterval(tick, 1000), setInterval(pollLage, 120000)] };
  renderLage();
  setTimeout(pollLage, 1500);
  return { main, top };
}

// ---------- Einhängepunkt: Seitenwechsel ----------
export function onRoute({ navHash }) {
  if (!R) return;
  const base = navHash.split("?")[0].replace(/\/$/, "") || "#";
  const key = base === "#" ? "#/" : base;
  R.app.classList.toggle("is-dash", key === "#/");
  window.scrollTo(0, 0);
}

// ---------- Einhängepunkt: Aufräumen beim Wechsel auf ein anderes Theme ----------
export function cleanup() {
  if (!R) return;
  if (kioskOn()) kiosk(false);
  R.timers.forEach(clearInterval);
  clearInterval(R.rotTimer);
  document.removeEventListener("keydown", R.onKey);
  document.removeEventListener("fullscreenchange", R.onFs);
  document.documentElement.classList.remove("ls-kiosk");
  R = null;
}

// ---------- Bausteine der Übersicht ----------
const panel = (area, title, body, extra = null, cls = "") => h("section", { class: `ls-pn ${area} ${cls}` },
  h("div", { class: "ls-ph" }, h("h2", null, title), h("span", { class: "sp" }), extra), h("div", { class: "ls-pb" }, body));

// Verlauf nach Stufe (gestapelt), zeichnet sich in Feldgröße neu
function stufenChart(box) {
  const svg = s("svg", { class: "ls-chart", role: "img", "aria-label": "Verlauf der Angriffe nach Stufe" });
  box.append(svg);
  let ov = null;
  const fmtAx = (ms, span) => {
    const d = new Date(ms);
    return span > 2 * 86400e3 ? `${d.getDate()}.${d.getMonth() + 1}.` : d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });
  };
  function draw() {
    const W = box.clientWidth, H = box.clientHeight;
    if (W < 60 || H < 50 || !ov || !ov.hist?.length) { svg.replaceChildren(); return; }
    const n = ov.hist.length, span = ov.step * n;
    const tot = ov.hist.map((c) => c.reduce((p, q) => p + q, 0));
    const top = Math.ceil(Math.max(4, ...tot) / 4) * 4;
    const L = 38, Rr = 6, T = 8, B = 18, bw = (W - L - Rr) / n, y = (v) => T + (H - T - B) * (1 - v / top);
    const k = [];
    for (let g = 0; g <= 4; g++) {
      const v = (top / 4) * g;
      k.push(s("line", { class: "grid", x1: L, x2: W - Rr, y1: y(v), y2: y(v) }), s("text", { x: L - 6, y: y(v) + 3.5, "text-anchor": "end" }, fmtNum(v)));
    }
    ov.hist.forEach((col, i) => {
      let acc = 0;
      col.forEach((v, st) => {
        if (!v) return;
        k.push(s("rect", { x: L + i * bw + 0.5, width: Math.max(0.8, bw - 1), y: y(acc + v), height: Math.max(0.5, y(acc) - y(acc + v)), fill: sevColor(st) }));
        acc += v;
      });
      const hit = s("rect", { x: L + i * bw, width: bw, y: T, height: H - T - B, fill: "transparent" });
      hoverTip(hit, () => [`${fmtAx(ov.from + i * ov.step, 0)}: ${fmtNum(tot[i])} Angriffe`, col.map((c, j) => (c ? [STUFE[j], fmtNum(c), sevColor(j)] : null)).filter(Boolean)]);
      k.push(hit);
    });
    const per = Math.max(1, Math.ceil(n / Math.max(2, Math.floor((W - L) / 70))));
    for (let i = 0; i < n; i += per) k.push(s("text", { x: L + i * bw, y: H - 4 }, fmtAx(ov.from + i * ov.step, span)));
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.replaceChildren(...k);
  }
  const ro = new ResizeObserver(draw);
  ro.observe(box);
  return { set(v) { ov = v; draw(); }, stop: () => ro.disconnect() };
}

const legend = () => h("div", { class: "ls-legend" }, STUFE_KURZ.map((st, i) => h("span", null, h("i", { style: { background: sevColor(i) } }), st)));

// ---------- Einhängepunkt: Übersicht ----------
export async function dashboard(el, ctx, d) {
  const r = d.range;
  const stufeOf = new Map(); // IP -> höchste bekannte Stufe (aus "Gerade aktiv" und Live)
  const arcColor = (ip) => (stufeOf.has(ip) ? sevColor(stufeOf.get(ip)) : null);
  const map = worldMap(d.mp, { home: d.home, countries: d.countries, arcs: "spur", arcColor });
  const origin = h("div", { class: "ls-origin" });
  map.el.querySelector(".mapbox")?.append(origin);

  const kpiBox = h("div", { class: "ls-kpis" });
  const topUl = h("ul", { class: "ls-rows" }), svcUl = h("ul", { class: "ls-rows" }), funBody = h("div", { class: "ls-fun" });
  const chartBox = h("div", { class: "ls-chartbox" });
  const chart = stufenChart(chartBox);
  ctx.onCleanup(chart.stop);
  const warn = h("div", { class: "ls-warn" });

  // ---- Ticker ----
  let tickMin = 0, paused = false;
  const tick = h("ul", { class: "ls-tick", "aria-live": "off" });
  const recent = []; // letzte Ereignisse für Filterwechsel
  const tkItem = (e) => {
    const st = stufeOf.get(e.src_ip) ?? 0;
    return h("li", { class: "ls-tk", style: { "--c": sevColor(st) } },
      h("time", { class: "num" }, fmtTime(e.ts)),
      h("div", { class: "tk-m" },
        h("div", { class: "tk-1" }, h("a", { class: "mono ip", href: "#/attacker/" + encodeURIComponent(e.src_ip) }, e.src_ip), " ", flag(e.country), " ", e.city || countryName(e.country)),
        h("div", { class: "tk-2" }, h("b", null, svcName(e.service)), " ", TYPE_NAME[e.type] || e.type, " ", h("span", { class: "muted" }, describe(e)))),
      h("span", { class: "ls-sv" }, STUFE_KURZ[st]));
  };
  const showable = (e) => e.src_ip && e.type !== "disconnect" && e.type !== "client_version" && (stufeOf.get(e.src_ip) ?? 0) >= tickMin;
  const fillTick = () => mount(tick, recent.filter(showable).slice(0, 60).map(tkItem));
  const addTick = (e) => {
    recent.unshift(e);
    if (recent.length > 300) recent.length = 300;
    if (paused || !showable(e)) return;
    tick.prepend(tkItem(e));
    while (tick.children.length > 60) tick.lastChild.remove();
  };
  const tkSeg = h("div", { class: "seg", role: "group", "aria-label": "Ticker-Filter" }, [["Alle", 0], ["ab Stufe 2", 2], ["ab Stufe 3", 3]].map(([l, v]) => h("button", {
    type: "button", class: v === tickMin ? "on" : null, "aria-pressed": String(v === tickMin),
    onclick: (ev) => { tickMin = v; tkSeg.querySelectorAll("button").forEach((b) => { b.classList.toggle("on", b === ev.currentTarget); b.setAttribute("aria-pressed", String(b === ev.currentTarget)); }); fillTick(); },
  }, l)));
  const pauseBtn = h("button", { class: "btn small", type: "button", "aria-pressed": "false", onclick: () => {
    paused = !paused;
    pauseBtn.textContent = paused ? "Weiter" : "Pause";
    pauseBtn.setAttribute("aria-pressed", String(paused));
    if (!paused) fillTick();
  } }, "Pause");

  // ---- Felder füllen (auch bei der Aktualisierung) ----
  const live = { connect: null };
  function fill(d) {
    const { ser } = d;
    mount(warn, warningsBox(d.sys && d.sys.warnings, true));
    const kp = (key, label, href, cls, sub) => {
      const v = Number(ser.totals[key] || 0), p = Number(ser.prev[key] || 0);
      const delta = p ? Math.round(((v - p) / p) * 100) : null;
      const big = h("div", { class: "big num" }, fmtNum(v));
      if (key === "connect") live.connect = { el: big, n: v };
      return h("a", { class: "ls-kp" + (cls && v ? " " + cls : ""), href, title: p ? `Zeitraum davor: ${fmtNum(p)}. Klick zeigt die Liste dazu.` : "Klick zeigt die Liste dazu." },
        h("span", { class: "lbl" }, label), big,
        h("span", { class: "sub" }, sub || "", delta !== null && delta !== 0 ? h("span", { class: delta > 0 ? "up" : "down" }, `${delta > 0 ? "▲" : "▼"} ${Math.abs(delta)} %`) : null),
        sparkline(ser.series[key] || [], { w: 160, hh: 22 }));
    };
    mount(kpiBox,
      kp("connect", "Verbindungen", `#/attacks?range=${r}`),
      kp("ips", "Angreifer-IPs", `#/attacks?range=${r}`, "", `${fmtNum(d.countries.length)} Länder`),
      kp("login", "Login-Versuche", "#/feed?type=login"),
      kp("success", "Login angenommen", `#/attacks?range=${r}&success=1`, "warn"),
      kp("fetch", "Nachladeversuche", `#/attacks?range=${r}&q=nachladen:ja`, "crit"));
    // Top-Angreifer
    mount(topUl, d.ips.length ? d.ips.slice(0, 8).map((x, i) => h("li", null, h("a", { class: "ls-top", href: "#/attacker/" + encodeURIComponent(x.key) },
      h("span", { class: "rk" }, i + 1), flag(x.label) || h("span"), h("span", { class: "mono nm" }, x.key),
      h("span", { class: "num muted" }, fmtNum(x.n)),
      h("span", { class: "pip", style: { "--c": stufeOf.has(x.key) ? sevColor(stufeOf.get(x.key)) : "transparent" }, title: stufeOf.has(x.key) ? STUFE[stufeOf.get(x.key)] + " (gerade aktiv)" : "" }))))
      : h("li", { class: "empty" }, "Keine Angreifer im Zeitraum."));
    // Dienste nach Anteil der Verbindungen
    const bySvc = new Map();
    for (const p of d.ports) bySvc.set(p.label || "other", (bySvc.get(p.label || "other") || 0) + Number(p.n || 0));
    const sv = [...bySvc].sort((a, b) => b[1] - a[1]).slice(0, 8), tot = Math.max(1, sv.reduce((t, [, n]) => t + n, 0)), mx = sv.length ? sv[0][1] : 1;
    mount(svcUl, sv.length ? sv.map(([k, n]) => h("li", { class: "ls-svc" }, h("span", null, svcName(k)), h("span", { class: "meter" }, h("i", { style: { width: (n / mx) * 100 + "%" } })),
      h("span", { class: "num muted" }, Math.round((n / tot) * 100) + " %"))) : h("li", { class: "empty" }, "Noch keine Verbindungen."));
    // Karte und Herkunft
    map.setData(d.mp, d.countries);
    const tc = d.countries.slice(0, 4), tm = tc.length ? Number(tc[0].n) : 1;
    mount(origin, tc.map((c) => h("div", null, flag(c.key) || h("span"), h("span", null, c.label || countryName(c.key)), h("span", { class: "num" }, fmtNum(c.n)),
      h("i", { class: "bar", style: { width: (Number(c.n) / tm) * 100 + "%" } }))));
  }
  async function fillExtra() {
    const [ov, fu] = await Promise.all([
      api(`attacks?range=${encodeURIComponent(r)}&limit=1&overview=1`).then((x) => x.overview).catch(() => null),
      api("funde?range=" + encodeURIComponent(/^\d+[hdwm]$/.test(r) ? r : "7d")).catch(() => null),
    ]);
    if (!ctx.current()) return;
    chart.set(ov);
    const f = fu && fu.funnel;
    if (!f) { mount(funBody, h("p", { class: "muted" }, "Funde gerade nicht abrufbar.")); return; }
    const steps = [["geholt", f.fetched || 0], ["Schadsoftware", f.malware || 0], ["an URLhaus gemeldet", (f.urlhaus_ok || 0) + (f.urlhaus_error || 0)]];
    const mxn = Math.max(1, f.seen || 0);
    mount(funBody, h("div", { class: "big num" + (f.malware ? " crit" : ""), title: "Nachlade-Adressen in Befehlen und Downloads" }, fmtNum(f.seen || 0)),
      h("div", { class: "fl" }, steps.map(([l, n]) => h("div", { class: "st" }, h("span", null, l), h("b", { class: "num" }, fmtNum(n)), h("span", { class: "meter" }, h("i", { style: { width: (n / mxn) * 100 + "%" } })))),
        h("a", { href: "#/funde" }, "Zu den Funden und Fallakten →")));
  }

  mount(el, h("div", { class: "ls-dash" },
    warn,
    h("section", { class: "ls-pn a-kpi" }, kpiBox),
    panel("a-map", "Herkunft der Angriffe", map.el, map.controls),
    panel("a-ver", "Verlauf nach Stufe", chartBox, legend()),
    h("section", { class: "ls-pn a-tick" },
      h("div", { class: "ls-ph" }, h("h2", null, "Live-Ticker"), h("span", { class: "sp" }), pauseBtn),
      h("div", { class: "ls-ph sub" }, tkSeg),
      h("div", { class: "ls-pb" }, tick)),
    panel("a-top", "Top-Angreifer", topUl, h("span", { class: "hint" }, "Verbindungen")),
    panel("a-svc", "Dienste", svcUl, h("span", { class: "hint" }, "Anteil Verbindungen")),
    panel("a-fun", "Funde", funBody, h("span", { class: "hint" }, "Nachlade-Adressen"))));
  fill(d);
  fillExtra();

  // Ticker mit den letzten Ereignissen vorbelegen, danach live
  api("events?limit=100").then((rows) => {
    if (!ctx.current()) return;
    for (const e of (rows || []).slice().reverse()) recent.unshift(e);
    fillTick();
  }).catch(() => {});

  // Gerade aktiv: Stufen für Farben und Lage, ruhige Bögen der letzten 15 Minuten
  d.actP.then((act) => {
    if (!act || !ctx.current()) return;
    for (const a of act.attacks) if (!a.own) stufeOf.set(a.ip, Math.max(stufeOf.get(a.ip) ?? 0, a.stufe));
    map.seedActive(act.attacks.filter((a) => !a.own));
    setLage(act.attacks);
    fillTick();
  });
  let actList = [];
  d.actP.then((act) => { actList = (act && act.attacks) || []; });
  ctx.live((e) => {
    map.track(e);
    addTick(e);
    if (e.type === "connect" && live.connect) { live.connect.n++; live.connect.el.textContent = fmtNum(live.connect.n); }
  });
  liveAttacks(ctx, (updated) => {
    for (const a of updated) {
      if (a.own) continue;
      stufeOf.set(a.ip, a.stufe);
      map.recolor(a.ip);
      const i = actList.findIndex((x) => x.id === a.id);
      if (i >= 0) actList[i] = a; else actList.push(a);
    }
    setLage(actList);
  });
  // Daten im Hintergrund auffrischen, ohne die Karte (und ihre Bögen) neu aufzubauen
  ctx.every(60000, async () => {
    if (document.hidden) return;
    try {
      const nd = await loadDashboard(r);
      if (!ctx.current() || state.range !== r) return;
      fill(nd);
      fillExtra();
      nd.actP.then((act) => { if (act && ctx.current()) { actList = act.attacks; setLage(actList); } });
    } catch { /* nächster Versuch */ }
  });
  ctx.every(30000, () => setLage(actList)); // Lage altert auch ohne neue Meldungen
}
