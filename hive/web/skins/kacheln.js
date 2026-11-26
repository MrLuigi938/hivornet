// Theme „Kacheln“: weicher Look mit schwebender Pillen-Leiste (Entwurf konzepte/themes/4-kacheln.html).
// Einhängepunkte (themes.js): shell (Pillen-Leiste oben, bleibt beim Scrollen sichtbar), onRoute
// (Übergang von der Kachel zur vollen Seite), dashboard (Bento-Raster aus Kacheln mit Anordnen-Modus),
// cleanup. Alle übrigen Seiten bleiben die des Standards und werden nur über skins/kacheln.css angepasst.
// Gemerkt im Browser (store): Anordnung der Kacheln ("kcLayout") und Akzentfarbe ("kcAkzent").
import { h, s, mount, api, fmtNum, flag, store, hoverTip, relTime, credText, ACTIVE_MS } from "../dom.js";
import { worldMap, sparkline, svcName, countryName, REGIONS } from "../charts.js";
import { STUFE, STUFE_KURZ, sevColor, liveAttacks, summary } from "../attacks.js";
import { state, loadDashboard, warningsBox } from "../app.js";
import { colorMode, setColorMode } from "../themes.js";

// ---------- Symbole (Linien, 24er Raster) ----------
const IC = {
  open: "M7 17 17 7M8 7h9v9", left: "M15 18 9 12l6-6", right: "m9 18 6-6-6-6", size: "M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7",
  hide: "M18 6 6 18M6 6l12 12", grid: "M3 3h8v8H3zM13 3h8v5h-8zM13 10h8v11h-8zM3 13h8v8H3z",
  moon: "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z",
  sun: "M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0z",
};
const svgi = (k) => s("svg", { viewBox: "0 0 24 24", "aria-hidden": "true", class: "kc-ic" }, s("path", { d: IC[k] }));
const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

// Akzentfarben: ein Farbwinkel (--h) für Akzent, Kopfkachel und Karte
const AKZENTE = [["285", "Violett"], ["18", "Koralle"], ["160", "Smaragd"], ["235", "Azur"], ["340", "Beere"]];
const akzent = () => (AKZENTE.some(([v]) => v === store("kcAkzent")) ? store("kcAkzent") : AKZENTE[0][0]);
const applyAkzent = () => { document.documentElement.dataset.kcAkzent = akzent(); };

// ---------- Zustand des Rahmens ----------
let R = null; // { root, main, pills, modeBtn, mq, onMq, from, scrollMem, restore }

const isDark = () => {
  const m = colorMode();
  return m === "system" ? !matchMedia("(prefers-color-scheme: light)").matches : m !== "light";
};
function modeIcon() {
  if (!R) return;
  const dark = isDark();
  mount(R.modeBtn, svgi(dark ? "sun" : "moon"));
  R.modeBtn.setAttribute("aria-label", dark ? "Hell anzeigen" : "Dunkel anzeigen");
  R.modeBtn.title = dark ? "Hell anzeigen (Farbmodus gilt für diesen Browser)" : "Dunkel anzeigen (Farbmodus gilt für diesen Browser)";
}

// ---------- Einhängepunkt: Rahmen ----------
export function shell(app, teile) {
  cleanup();
  applyAkzent();
  const pills = h("nav", { class: "kc-pills", "aria-label": "Hauptnavigation" },
    teile.nav.map(([href, label]) => h("a", { class: "kc-pill", href, "data-navlink": "" }, label)));
  const modeBtn = h("button", { class: "kc-ib", type: "button", onclick: () => { setColorMode(isDark() ? "light" : "dark"); modeIcon(); } });
  const top = h("div", { class: "top kc-head" });
  const main = h("div", { class: "kc-view" });
  const root = h("div", { class: "kc-app" },
    h("div", { class: "kc-dock" },
      h("div", { class: "kc-bar" }, teile.brand, pills, h("span", { class: "kc-sp" }), teile.live, modeBtn, teile.userMenu)),
    h("main", { class: "kc-main" }, top, main, teile.credit));
  mount(app, root);
  const mq = matchMedia("(prefers-color-scheme: light)");
  const onMq = () => modeIcon();
  mq.addEventListener("change", onMq);
  R = { root, main: root.querySelector(".kc-main"), pills, modeBtn, mq, onMq, from: null, scrollMem: 0, restore: null };
  modeIcon();
  return { main, top };
}

// ---------- Einhängepunkt: Seitenwechsel (weicher Übergang von der Kachel zur Seite) ----------
export function onRoute({ hash }) {
  if (!R) return;
  const dash = /^#?\/?$/.test(hash);
  R.root.classList.toggle("is-dash", dash);
  const from = R.from;
  R.from = null;
  // aktive Pille in der (auf dem Handy scrollbaren) Leiste sichtbar halten
  const on = R.pills.querySelector(".on");
  if (on) {
    const pr = R.pills.getBoundingClientRect(), or = on.getBoundingClientRect();
    if (or.left < pr.left || or.right > pr.right) R.pills.scrollLeft += or.left - pr.left - (pr.width - or.width) / 2;
  }
  if (dash) { R.restore = R.scrollMem; R.scrollMem = 0; }
  window.scrollTo(0, 0);
  const el = R.main;
  if (!el.animate || reduced()) return;
  if (from && !dash) {
    const vr = el.getBoundingClientRect();
    const t = Math.max(0, from.top - vr.top), l = Math.max(0, from.left - vr.left);
    const r = Math.max(0, vr.right - from.right), b = Math.max(0, vr.bottom - from.bottom);
    el.animate([{ clipPath: `inset(${t}px ${r}px ${b}px ${l}px round 24px)`, opacity: 0.55 }, { clipPath: "inset(0px 0px 0px 0px round 0px)", opacity: 1 }],
      { duration: 420, easing: "cubic-bezier(.2,.8,.2,1)" });
  } else {
    el.animate([{ opacity: 0, transform: "translateY(8px)" }, { opacity: 1, transform: "none" }], { duration: 220, easing: "ease-out" });
  }
}

// ---------- Einhängepunkt: Aufräumen beim Wechsel auf ein anderes Theme ----------
export function cleanup() {
  delete document.documentElement.dataset.kcAkzent;
  if (!R) return;
  R.mq.removeEventListener("change", R.onMq);
  R = null;
}

// Kachel öffnet die volle Seite; der Übergang startet an der Stelle der Kachel
function openTile(el, href) {
  if (R) { R.from = el.getBoundingClientRect(); R.scrollMem = window.scrollY; }
  if (location.hash === href) return;
  location.hash = href;
}

// ---------- Bausteine ----------
function rangeText(r) {
  const m = /^(\d+)([hdwm])$/.exec(r || "");
  if (!m) return "im Zeitraum";
  const n = Number(m[1]);
  const t = { h: ["in der letzten Stunde", "Stunden"], d: ["im letzten Tag", "Tagen"], w: ["in der letzten Woche", "Wochen"], m: ["im letzten Monat", "Monaten"] }[m[2]];
  return n === 1 ? t[0] : `in den letzten ${fmtNum(n)} ${t[1]}`;
}
const greet = () => { const hr = new Date().getHours(); return hr < 11 ? "Guten Morgen" : hr < 18 ? "Guten Tag" : "Guten Abend"; };
const chip = (text, c) => h("span", { class: "kc-chip", style: c ? { "--c": c } : null }, text);
const empty = (t) => h("p", { class: "kc-empty" }, t);

// Verlauf nach Stufe (gestapelt), zeichnet sich in Kachelgröße neu
function stufenChart(box) {
  const svg = s("svg", { class: "kc-chart", role: "img", "aria-label": "Verlauf der Angriffe nach Stufe" });
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
    const L = 34, Rr = 2, T = 6, B = 18, bw = (W - L - Rr) / n, y = (v) => T + (H - T - B) * (1 - v / top);
    const k = [];
    for (let g = 0; g <= 4; g++) {
      const v = (top / 4) * g;
      k.push(s("line", { class: "grid", x1: L, x2: W - Rr, y1: y(v), y2: y(v) }), s("text", { x: L - 6, y: y(v) + 3.5, "text-anchor": "end" }, fmtNum(v)));
    }
    const gap = bw > 6 ? 1.5 : 0.5;
    ov.hist.forEach((col, i) => {
      let acc = 0;
      col.forEach((v, st) => {
        if (!v) return;
        k.push(s("rect", { x: L + i * bw + gap / 2, width: Math.max(0.8, bw - gap), y: y(acc + v), height: Math.max(0.5, y(acc) - y(acc + v)), rx: Math.min(3, bw / 4), fill: sevColor(st) }));
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

// ---------- Kachel-Katalog ----------
// sizes: erlaubte Größen "BreitexHöhe" (Spalten von 12, Zeilen); die erste ist die Vorgabe.
// to(r): volle Seite des Hive zur Kachel (r = Zeitraum der Übersicht).
const TILES = {
  hero: { title: "Lage", sizes: ["6x4", "12x4"], to: (r) => `#/attacks?range=${r}`, cls: "kc-hero" },
  adr: { title: "Angreifer-Adressen", sizes: ["3x2", "6x2"], to: (r) => `#/attacks?range=${r}`, kpi: "ips", color: "var(--sev1)" },
  login: { title: "Login-Versuche", sizes: ["3x2", "6x2"], to: () => "#/feed?type=login", kpi: "login", color: "var(--sev1)" },
  ok: { title: "Logins angenommen", sizes: ["3x2", "6x2"], to: (r) => `#/attacks?range=${r}&success=1`, kpi: "success", color: "var(--sev2)", alarm: true },
  fetch: { title: "Nachladeversuche", sizes: ["3x2", "6x2"], to: (r) => `#/attacks?range=${r}&q=nachladen:ja`, kpi: "fetch", color: "var(--sev4)", alarm: true },
  verlauf: { title: "Verlauf nach Stufe", sizes: ["8x4", "12x4", "6x4"], to: (r) => `#/attacks?range=${r}` },
  aktiv: { title: "Gerade aktiv", sizes: ["4x4", "4x5", "6x4"], to: () => "#/attacks" },
  karte: { title: "Herkunft der Angriffe", sizes: ["8x6", "12x6", "6x4"], to: () => "#/analysis" },
  trichter: { title: "Wie weit kamen sie?", sizes: ["4x3", "6x3", "4x4"], to: (r) => `#/attacks?range=${r}` },
  laender: { title: "Top-Herkunftsländer", sizes: ["4x3", "4x4", "6x3"], to: () => "#/analysis" },
  dienste: { title: "Angegriffene Dienste", sizes: ["4x3", "4x4"], to: () => "#/analysis" },
  zugang: { title: "Häufigste Zugangsdaten", sizes: ["4x3", "6x3"], to: () => "#/creds" },
  funde: { title: "Neueste Funde", sizes: ["4x3", "4x4", "6x4", "12x3"], to: () => "#/funde" },
};
const DEFAULT_ORDER = Object.keys(TILES);

// Anordnung aus dem Browser; nur bekannte Kacheln und erlaubte Größen
function loadLayout() {
  let raw = {};
  try { raw = JSON.parse(store("kcLayout") || "{}") || {}; } catch { raw = {}; }
  const ids = (a) => (Array.isArray(a) ? a.filter((id, i) => typeof id === "string" && Object.hasOwn(TILES, id) && a.indexOf(id) === i) : []);
  const order = ids(raw.order);
  const size = {};
  if (raw.size && typeof raw.size === "object") for (const [id, z] of Object.entries(raw.size)) if (Object.hasOwn(TILES, id) && TILES[id].sizes.includes(z)) size[id] = z;
  return { order: [...order, ...DEFAULT_ORDER.filter((id) => !order.includes(id))], hidden: ids(raw.hidden), size };
}

// ---------- Einhängepunkt: Übersicht ----------
export async function dashboard(el, ctx, d) {
  const r = d.range;
  let D = d, OV = null, FU = null, ACT = [], conn = 0, edit = false, drag = null;
  const L = loadLayout();
  const save = () => store("kcLayout", JSON.stringify(L));
  const sizeOf = (id) => L.size[id] || TILES[id].sizes[0];
  const stufeOf = new Map(); // IP -> höchste bekannte Stufe (Farbe der Bögen)
  const arcColor = (ip) => (stufeOf.has(ip) ? sevColor(stufeOf.get(ip)) : null);
  const map = worldMap(d.mp, { home: d.home, countries: d.countries, arcs: "spur", arcColor, controls: false });
  const chartBox = h("div", { class: "kc-chartbox" });
  const chart = stufenChart(chartBox);
  ctx.onCleanup(chart.stop);
  const sr = h("div", { class: "kc-sr", "aria-live": "polite" });
  const say = (t) => { sr.textContent = t; };

  // ---- Kopfzeile: Begrüßung, Zeitraum (aus header()), Anordnen ----
  const editBtn = h("button", { class: "btn kc-editbtn", type: "button", "aria-pressed": "false", onclick: () => setEdit(!edit) }, svgi("grid"), "Anordnen");
  const top = el.closest(".kc-app")?.querySelector(".kc-head");
  if (top && state.user) {
    const h1 = top.querySelector("h1");
    if (h1) h1.textContent = `${greet()}, ${state.user.username}`;
    top.querySelector(".range-pick")?.before(h("span", { class: "kc-sub" }, "Zeitraum"));
    top.append(editBtn);
  }

  // ---- Inhalte der Kacheln ----
  const active = () => {
    const now = Date.now();
    return ACT.filter((a) => !a.own && now - a.last < ACTIVE_MS).sort((x, y) => y.last - x.last);
  };
  const R_ = {
    hero(b) {
      const st = OV ? OV.stufen : null, total = st ? st.reduce((p, q) => p + q, 0) : null, zug = st ? st[2] + st[3] + st[4] : 0;
      const act = active(), lage = act.reduce((m, a) => Math.max(m, a.stufe), -1);
      conn = Number(D.ser.totals.connect || 0);
      mount(b,
        h("div", { class: "kc-big num" }, total === null ? "…" : fmtNum(total)),
        h("p", { class: "kc-lede" }, `Angriffe ${rangeText(r)}, `, total === null ? "…" : zug ? `davon ${fmtNum(zug)} mit angenommenem Login.` : "keiner mit angenommenem Login."),
        h("div", { class: "kc-chips" },
          chip(lage >= 0 ? `Lage: ${STUFE[lage]}` : "Lage: ruhig", lage >= 0 ? sevColor(lage) : "var(--good)"),
          chip(`${fmtNum(D.ser.totals.ips || 0)} Adressen`),
          chip(`${fmtNum(act.length)} aktiv`),
          h("span", { class: "kc-chip", "data-conn": "" }, `${fmtNum(conn)} Verbindungen`)),
        sparkline(D.ser.series.connect || [], { w: 160, hh: 40 }));
    },
    verlauf(b) {
      if (!b.firstChild) mount(b, h("div", { class: "kc-legend" }, STUFE_KURZ.map((x, i) => h("span", { style: { "--c": sevColor(i) }, title: STUFE[i] }, x))), chartBox);
      chart.set(OV);
    },
    aktiv(b) {
      const act = active();
      if (!act.length) return mount(b, empty("Gerade ist niemand aktiv. Neue Angriffe erscheinen hier sofort."));
      mount(b, h("div", { class: "kc-rows" }, act.slice(0, 10).map((a) => h("a", { class: "kc-row", href: "#/attacker/" + encodeURIComponent(a.ip) },
        flag(a.country) || h("span", { class: "flag" }), h("span", { class: "mid" }, h("span", { class: "mono" }, a.ip), h("small", null, summary(a))),
        h("span", { class: "kc-dot", style: { "--c": sevColor(a.stufe) }, title: STUFE[a.stufe] }),
        h("span", { class: "r" }, relTime(a.last).replace(/^vor /, ""))))));
    },
    karte(b) {
      if (!b.firstChild) {
        mount(b, h("div", { class: "kc-mapbox" }, map.el,
          h("div", { class: "kc-zoom" }, Object.keys(REGIONS).map((k) => h("button", { type: "button", onclick: (e) => { e.stopPropagation(); map.zoom(k); } }, k)))));
      } else map.setData(D.mp, D.countries);
    },
    trichter(b) {
      if (!OV) return mount(b, empty("Lade …"));
      const fun = [0, 1, 2, 3, 4].map((i) => OV.stufen.slice(i).reduce((p, q) => p + q, 0)), mx = Math.max(1, fun[0]);
      mount(b, h("div", { class: "kc-fun" }, STUFE_KURZ.map((x, i) => h("div", { style: { "--c": sevColor(i) }, title: `${STUFE[i]} oder weiter: ${fmtNum(fun[i])} Angriffe` },
        h("span", null, x), h("span", { class: "trk" }, h("i", { style: { width: (fun[i] / mx) * 100 + "%" } })), h("b", null, fmtNum(fun[i]))))));
    },
    laender(b) {
      const rows = D.countries.slice(0, 7), mx = rows.length ? Number(rows[0].n) : 1;
      if (!rows.length) return mount(b, empty("Noch keine Herkunft im Zeitraum."));
      mount(b, h("div", { class: "kc-hbars" }, rows.map((c) => h("div", { class: "kc-hbar" }, flag(c.key) || h("span", { class: "flag" }),
        h("span", { class: "nm" }, c.label || countryName(c.key)), h("b", null, fmtNum(c.n)), h("span", { class: "trk" }, h("i", { style: { width: (Number(c.n) / mx) * 100 + "%" } }))))));
    },
    dienste(b) {
      const by = new Map();
      for (const p of D.ports) by.set(p.label || "other", (by.get(p.label || "other") || 0) + Number(p.n || 0));
      const rows = [...by].sort((a, c) => c[1] - a[1]), tot = rows.reduce((t, [, n]) => t + n, 0);
      if (!tot) return mount(b, empty("Noch keine Verbindungen im Zeitraum."));
      const top5 = rows.slice(0, 5), rest = tot - top5.reduce((t, [, n]) => t + n, 0);
      const items = [...top5.map(([k, n], i) => [svcName(k), n, `var(--s${i + 1})`]), ...(rest > 0 ? [["Übrige", rest, "var(--other)"]] : [])];
      let off = 0;
      const svg = s("svg", { viewBox: "0 0 36 36", "aria-hidden": "true" }, s("circle", { class: "track", cx: 18, cy: 18, r: 15.9155 }),
        items.map(([, n, col]) => {
          const p = (n / tot) * 100;
          const c = s("circle", { cx: 18, cy: 18, r: 15.9155, stroke: col, "stroke-dasharray": `${Math.max(0, p - 0.8)} ${100 - p + 0.8}`, "stroke-dashoffset": -off });
          off += p;
          return c;
        }));
      mount(b, h("div", { class: "kc-donut" }, svg, h("ul", null, items.map(([n, v, col]) => h("li", { style: { "--c": col } }, h("span", null, n), h("b", null, Math.round((v / tot) * 100) + " %"))))));
    },
    zugang(b) {
      const rows = (D.creds || []).slice(0, 10);
      if (!rows.length) return mount(b, empty("Noch keine Zugangsdaten im Zeitraum."));
      mount(b, h("div", { class: "kc-cred" }, rows.map((c) => h("span", null, h("span", { class: "mono" }, credText(c.key)), h("em", null, "×" + fmtNum(c.n))))));
    },
    funde(b) {
      if (!FU) return mount(b, empty(FU === false ? "Funde gerade nicht abrufbar." : "Lade …"));
      const urls = (FU.urls || []).slice().sort((a, c) => c.last - a.last).slice(0, 8);
      if (!urls.length) return mount(b, empty("Keine Funde im Zeitraum."));
      const why = (u) => (u.malware ? ["Schadsoftware", 4] : u.fetch === "ok" ? ["geholt", 3] : u.fetch === "error" ? ["nicht abrufbar", 2] : u.why ? ["nicht geholt", 1] : ["offen", 0]);
      mount(b, h("div", { class: "kc-rows" }, urls.map((u) => {
        const [st, sv] = why(u);
        return h("a", { class: "kc-row", href: "#/funde" },
          h("span", { class: "mid" }, h("span", { class: "mono" }, u.host || u.url), h("small", null, `${st} · ${u.n_ips === 1 ? "1 Adresse" : `${fmtNum(u.n_ips || 0)} Adressen`}`)),
          h("span", { class: "kc-dot", style: { "--c": sevColor(sv) }, title: st }),
          h("span", { class: "r" }, relTime(u.last).replace(/^vor /, "")));
      })));
    },
  };
  // Kennzahlen mit Verlauf und Vergleich zum Zeitraum davor
  for (const [id, t] of Object.entries(TILES)) if (t.kpi) R_[id] = (b) => {
    const v = Number(D.ser.totals[t.kpi] || 0), p = Number(D.ser.prev[t.kpi] || 0);
    const delta = p >= 20 ? Math.round(((v - p) / p) * 100) : null;
    b.closest(".kc-tile").classList.toggle("is-alarm", Boolean(t.alarm && v));
    mount(b, h("div", { class: "kc-big num" }, fmtNum(v)),
      h("div", { class: "kc-delta" }, delta !== null && delta !== 0 ? h("span", { class: delta > 0 ? "up" : "down" }, `${delta > 0 ? "▲" : "▼"} ${Math.abs(delta)} %`) : null,
        p ? ` Zeitraum davor: ${fmtNum(p)}` : ""),
      sparkline(D.ser.series[t.kpi] || [], { w: 160, hh: 30 }));
  };

  // ---- Kacheln bauen ----
  const tiles = new Map();
  const grid = h("div", { class: "kc-grid" });
  function makeTile(id) {
    const t = TILES[id];
    const body = h("div", { class: "kc-body" });
    const href = t.to(r);
    const ctlBtn = (ic, label, fn) => h("button", { type: "button", "aria-label": `${t.title}: ${label}`, title: label, onclick: (e) => { e.stopPropagation(); fn(e); } }, svgi(ic));
    const tile = h("section", { class: "kc-tile" + (t.cls ? " " + t.cls : "") + (t.kpi ? " kc-kpi" : ""), "data-id": id, tabindex: "0", "aria-label": t.title,
      onclick: (e) => { if (edit || e.target.closest("a, button, input, select, .kc-mapbox")) return; openTile(tile, href); },
      onkeydown: (e) => onTileKey(e, id, tile, href),
      onpointerdown: (e) => dragStart(e, id, tile) },
    h("header", { class: "kc-th" },
      t.kpi ? h("span", { class: "kc-ico", style: { "--c": t.color } }, h("i")) : null,
      h("h2", null, t.title),
      h("a", { class: "kc-open", href, "aria-label": `${t.title}: volle Seite öffnen`, title: "Volle Seite öffnen", onclick: (e) => { e.preventDefault(); e.stopPropagation(); openTile(tile, href); } }, svgi("open")),
      h("span", { class: "kc-ctl" },
        ctlBtn("left", "Eine Position früher", () => move(id, -1)),
        ctlBtn("right", "Eine Position später", () => move(id, 1)),
        ctlBtn("size", "Größe wechseln", () => resize(id)),
        ctlBtn("hide", "Ausblenden", () => hide(id)))),
    body);
    tiles.set(id, { el: tile, body });
    return tile;
  }
  for (const id of L.order) grid.append(makeTile(id));

  const renderTile = (id) => {
    if (L.hidden.includes(id) || !R_[id]) return;
    try { R_[id](tiles.get(id).body); } catch (e) { console.error(`Kachel ${id}:`, e); }
  };
  const renderAll = () => { if (!drag) L.order.forEach(renderTile); };

  // ---- Anordnung: Reihenfolge, Größe, Ausblenden ----
  // Beim Ziehen nur CSS-order (kein Umhängen im DOM), danach DOM-Reihenfolge = Anzeige (Tab-Reihenfolge).
  function applyLayout(animate, useOrder = false) {
    const before = animate && !reduced() ? new Map([...grid.children].map((c) => [c, c.getBoundingClientRect()])) : null;
    const vis = L.order.filter((id) => !L.hidden.includes(id));
    L.order.forEach((id, i) => {
      const { el: t } = tiles.get(id);
      const [w, hh] = sizeOf(id).split("x");
      for (const c of [...t.classList]) if (/^kc-[wh]\d+$/.test(c)) t.classList.remove(c);
      t.classList.add("kc-w" + w, "kc-h" + hh);
      t.hidden = L.hidden.includes(id);
      if (useOrder) t.style.order = String(vis.indexOf(id));
      else {
        t.style.order = "";
        if (grid.children[i] !== t) grid.insertBefore(t, grid.children[i] || null);
      }
    });
    if (before) for (const c of grid.children) {
      if (drag && c === drag.el) continue;
      const a = before.get(c), b = c.getBoundingClientRect();
      if (a && a.width && b.width && (Math.abs(a.left - b.left) > 1 || Math.abs(a.top - b.top) > 1)) {
        c.animate([{ transform: `translate(${a.left - b.left}px, ${a.top - b.top}px)` }, { transform: "none" }], { duration: 260, easing: "cubic-bezier(.2,.8,.2,1)" });
      }
    }
    drawTray();
  }
  const visible = () => L.order.filter((x) => !L.hidden.includes(x));
  function move(id, dir) {
    const vis = visible(), i = vis.indexOf(id), j = i + dir;
    if (i < 0 || j < 0 || j >= vis.length) return;
    const fe = document.activeElement;
    L.order.splice(L.order.indexOf(id), 1);
    L.order.splice(L.order.indexOf(vis[j]) + (dir > 0 ? 1 : 0), 0, id);
    save();
    applyLayout(true);
    if (fe && fe !== document.activeElement && fe.isConnected) fe.focus();
    say(`${TILES[id].title}: Position ${j + 1} von ${vis.length}`);
  }
  function resize(id) {
    const z = TILES[id].sizes, i = z.indexOf(sizeOf(id)), next = z[(i + 1) % z.length];
    if (next === z[0]) delete L.size[id]; else L.size[id] = next;
    save();
    applyLayout(true);
    say(`${TILES[id].title}: Größe ${next.replace("x", " × ")}`);
  }
  function hide(id) {
    const vis = visible(), i = vis.indexOf(id);
    L.hidden.push(id);
    save();
    applyLayout(true);
    say(`${TILES[id].title} ausgeblendet, liegt in der Ablage`);
    const next = visible()[Math.min(i, visible().length - 1)];
    (next ? tiles.get(next).el : tray.querySelector("button"))?.focus();
  }
  function show(id) {
    L.hidden = L.hidden.filter((x) => x !== id);
    save();
    applyLayout(true);
    renderTile(id);
    tiles.get(id).el.focus();
    say(`${TILES[id].title} wieder eingeblendet`);
  }

  // ---- Ablage (unten): ausgeblendete Kacheln, Akzentfarbe, Zurücksetzen, Fertig ----
  const tray = h("div", { class: "kc-tray", role: "region", "aria-label": "Anordnen", hidden: true });
  function drawTray() {
    mount(tray,
      h("span", { class: "lbl" }, "Ablage:"),
      h("span", { class: "hid" }, L.hidden.length
        ? L.hidden.map((id) => h("button", { type: "button", title: "Wieder einblenden", onclick: () => show(id) }, "+ " + TILES[id].title))
        : h("span", { class: "muted" }, "nichts ausgeblendet")),
      h("span", { class: "kc-sp" }),
      h("span", { class: "kc-swatches", role: "group", "aria-label": "Akzentfarbe" }, h("span", { class: "lbl" }, "Farbe"),
        AKZENTE.map(([v, n]) => h("button", { class: "kc-sw", type: "button", "data-h": v, "aria-label": n, title: n, "aria-pressed": String(akzent() === v),
          onclick: () => { store("kcAkzent", v); applyAkzent(); drawTray(); tray.querySelector(`[data-h="${v}"]`)?.focus(); } }))),
      h("button", { class: "btn", type: "button", onclick: () => {
        L.order = [...DEFAULT_ORDER]; L.hidden = []; L.size = {};
        save(); applyLayout(true); renderAll(); say("Anordnung zurückgesetzt");
      } }, "Zurücksetzen"),
      h("button", { class: "btn primary", type: "button", onclick: () => setEdit(false) }, "Fertig"));
  }
  const dash = h("div", { class: "kc-dash" });
  function setEdit(v) {
    edit = v;
    dash.classList.toggle("kc-edit", v);
    tray.hidden = !v;
    editBtn.setAttribute("aria-pressed", String(v));
    editBtn.classList.toggle("primary", v);
    say(v ? "Anordnen: Kacheln ziehen oder mit den Pfeiltasten verschieben, Entf blendet aus, Esc beendet." : "Anordnung gespeichert");
    if (!v) dragEnd();
  }

  // ---- Tastatur ----
  function onTileKey(e, id, tile, href) {
    if (e.target !== tile) return;
    if (!edit) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openTile(tile, href); } return; }
    const k = { ArrowLeft: -1, ArrowUp: -1, ArrowRight: 1, ArrowDown: 1 }[e.key];
    if (k) { e.preventDefault(); move(id, k); tile.focus(); }
    else if (e.key === "Delete" || e.key === "Backspace") { e.preventDefault(); hide(id); }
    else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); resize(id); }
  }
  const onKey = (e) => { if (edit && e.key === "Escape") setEdit(false); };
  document.addEventListener("keydown", onKey);
  ctx.onCleanup(() => document.removeEventListener("keydown", onKey));

  // ---- Ziehen mit Maus, Stift und Finger (Pointer-Events) ----
  // Maus: an der ganzen Kachel; Finger: am Kopf der Kachel, damit die Seite weiter scrollt.
  function dragStart(e, id, tile) {
    if (!edit || drag || (e.pointerType === "mouse" && e.button !== 0)) return;
    if (e.target.closest(".kc-ctl, a, button")) return;
    if (e.pointerType !== "mouse" && !e.target.closest(".kc-th")) return;
    e.preventDefault();
    const rc = tile.getBoundingClientRect();
    drag = { id, el: tile, pid: e.pointerId, sx: e.clientX, sy: e.clientY, x: e.clientX, y: e.clientY, offX: e.clientX - rc.left, offY: e.clientY - rc.top, on: false, lock: 0, raf: 0 };
    window.addEventListener("pointermove", dragMove);
    window.addEventListener("pointerup", dragUp);
    window.addEventListener("pointercancel", dragUp);
  }
  function place() {
    if (!drag) return;
    const g = grid.getBoundingClientRect();
    drag.el.style.transform = `translate(${drag.x - drag.offX - (g.left + drag.el.offsetLeft)}px, ${drag.y - drag.offY - (g.top + drag.el.offsetTop)}px)`;
  }
  function autoScroll() {
    if (!drag || !drag.on) return;
    const edge = 70, y = drag.y;
    const v = y < edge ? -Math.ceil((edge - y) / 5) : y > innerHeight - edge ? Math.ceil((y - innerHeight + edge) / 5) : 0;
    if (v) { window.scrollBy(0, v); place(); reorderAt(); }
    drag.raf = requestAnimationFrame(autoScroll);
  }
  function reorderAt() {
    const now = performance.now();
    if (now < drag.lock) return;
    const hit = document.elementsFromPoint(drag.x, drag.y).map((n) => n.closest?.(".kc-tile")).find((t) => t && t !== drag.el && grid.contains(t));
    if (!hit) return;
    const rc = hit.getBoundingClientRect();
    const after = drag.y > rc.top + rc.height * 0.6 || (drag.y > rc.top + rc.height * 0.3 && drag.x > rc.left + rc.width / 2);
    const o = L.order.filter((x) => x !== drag.id);
    o.splice(o.indexOf(hit.dataset.id) + (after ? 1 : 0), 0, drag.id);
    if (o.join() === L.order.join()) return;
    L.order = o;
    drag.lock = now + 220; // Kacheln erst ankommen lassen, sonst pendelt die Reihenfolge
    applyLayout(true, true);
    place();
  }
  function dragMove(e) {
    if (!drag || e.pointerId !== drag.pid) return;
    drag.x = e.clientX; drag.y = e.clientY;
    if (!drag.on) {
      if (Math.hypot(drag.x - drag.sx, drag.y - drag.sy) < 6) return;
      drag.on = true;
      drag.el.classList.add("kc-drag");
      dash.classList.add("kc-dragging");
      drag.raf = requestAnimationFrame(autoScroll);
    }
    e.preventDefault();
    place();
    reorderAt();
  }
  function dragUp(e) { if (drag && e.pointerId === drag.pid) dragEnd(true); }
  function dragEnd(drop = false) {
    window.removeEventListener("pointermove", dragMove);
    window.removeEventListener("pointerup", dragUp);
    window.removeEventListener("pointercancel", dragUp);
    if (!drag) return;
    const d0 = drag;
    drag = null;
    cancelAnimationFrame(d0.raf);
    if (!d0.on) return;
    const a = d0.el.getBoundingClientRect();
    d0.el.classList.remove("kc-drag");
    dash.classList.remove("kc-dragging");
    d0.el.style.transform = "";
    applyLayout(false);
    if (drop && d0.el.animate && !reduced()) {
      const b = d0.el.getBoundingClientRect();
      d0.el.animate([{ transform: `translate(${a.left - b.left}px, ${a.top - b.top}px)` }, { transform: "none" }], { duration: 220, easing: "cubic-bezier(.2,.8,.2,1)" });
    }
    save();
    const vis = visible();
    say(`${TILES[d0.id].title}: Position ${vis.indexOf(d0.id) + 1} von ${vis.length}`);
  }
  ctx.onCleanup(() => dragEnd());

  // ---- Seite aufbauen ----
  const warn = h("div", { class: "kc-warn" }, warningsBox(d.sys && d.sys.warnings, true));
  mount(el, h("div", { class: "kc-wrap" }, warn, mount(dash, grid), tray, sr));
  applyLayout(false);
  renderAll();
  if (R && R.restore) { const y = R.restore; R.restore = null; requestAnimationFrame(() => window.scrollTo(0, y)); }

  async function fillExtra() {
    const [ov, fu] = await Promise.all([
      api(`attacks?range=${encodeURIComponent(r)}&limit=1&overview=1`).then((x) => x.overview).catch(() => null),
      api("funde?range=" + encodeURIComponent(/^\d+[hdwm]$/.test(r) ? r : "7d")).catch(() => false),
    ]);
    if (!ctx.current()) return;
    OV = ov;
    FU = fu;
    for (const id of ["hero", "verlauf", "trichter", "funde"]) renderTile(id);
  }
  fillExtra();

  // Gerade aktiv: Stufen für Farben, ruhige Bögen der letzten 15 Minuten
  d.actP.then((act) => {
    if (!act || !ctx.current()) return;
    ACT = act.attacks || [];
    for (const a of ACT) if (!a.own) stufeOf.set(a.ip, Math.max(stufeOf.get(a.ip) ?? 0, a.stufe));
    map.seedActive(ACT.filter((a) => !a.own));
    renderTile("aktiv");
    renderTile("hero");
  });
  ctx.live((e) => {
    map.track(e);
    if (e.type === "connect") {
      conn++;
      const c = tiles.get("hero").body.querySelector("[data-conn]");
      if (c) c.textContent = `${fmtNum(conn)} Verbindungen`;
    }
  });
  liveAttacks(ctx, (updated) => {
    for (const a of updated) {
      if (a.own) continue;
      stufeOf.set(a.ip, a.stufe);
      map.recolor(a.ip);
      const i = ACT.findIndex((x) => x.id === a.id);
      if (i >= 0) ACT[i] = a; else ACT.push(a);
    }
    if (!drag) { renderTile("aktiv"); renderTile("hero"); }
  });
  // Daten im Hintergrund auffrischen, ohne die Karte (und ihre Bögen) neu aufzubauen
  ctx.every(60000, async () => {
    if (document.hidden || drag) return;
    try {
      const nd = await loadDashboard(r);
      if (!ctx.current() || state.range !== r) return;
      D = nd;
      mount(warn, warningsBox(nd.sys && nd.sys.warnings, true));
      renderAll();
      fillExtra();
      nd.actP.then((act) => { if (act && ctx.current()) { ACT = act.attacks || []; if (!drag) { renderTile("aktiv"); renderTile("hero"); } } });
    } catch { /* nächster Versuch */ }
  });
  ctx.every(30000, () => { if (!drag) { renderTile("aktiv"); renderTile("hero"); } }); // „vor x Min“ und Lage altern
}
