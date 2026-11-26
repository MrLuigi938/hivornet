// Theme „Taschenformat“: mobil zuerst (Entwurf konzepte/themes/6-taschenformat.html).
// Einhängepunkte (themes.js): shell (Ampel oben, Tableiste unten bzw. ab 900 px oben mittig,
// Blatt „Mehr“), onRoute (aktiver Reiter, Blatt schließen), dashboard (Kartenstapel mit
// „Seit deinem letzten Besuch“, Karte mit Vollbild-Blatt), cleanup.
// Alle übrigen Seiten bleiben die des Standards und werden nur über skins/taschenformat.css angepasst.
import { h, s, mount, api, fmtNum, fmtTime, flag, store, relTime, hoverTip, ACTIVE_MS } from "../dom.js";
import { worldMap, sparkline, svcName, svcColor, countryName } from "../charts.js";
import { STUFE, STUFE_KURZ, sevColor, liveAttacks } from "../attacks.js";
import { state, loadDashboard, warningsBox } from "../app.js";
import { COLOR_MODES, colorMode, setColorMode } from "../themes.js";

// ---------- Symbole (Linien, 24er Raster; Ampel im 36er Raster) ----------
const ICON = {
  home: [["path", { d: "M4 11.5 12 4l8 7.5V20H4z" }], ["path", { d: "M10 20v-6h4v6" }]],
  attacks: [["path", { d: "M12 3 3 19h18z" }], ["path", { d: "M12 10v4M12 17v.5" }]],
  funde: [["path", { d: "M6 3h8l4 4v14H6z" }], ["path", { d: "M14 3v4h4M9 13h6M9 17h4" }]],
  mehr: [["circle", { cx: 5, cy: 12, r: 1.6 }], ["circle", { cx: 12, cy: 12, r: 1.6 }], ["circle", { cx: 19, cy: 12, r: 1.6 }]],
  analysis: [["path", { d: "M4 20V10M10 20V4M16 20v-7M21 20H3" }]],
  insights: [["path", { d: "M9 18h6M10 21h4" }], ["path", { d: "M12 3a6 6 0 0 0-3.5 10.9c.6.5 1 1.2 1 2.1h5c0-.9.4-1.6 1-2.1A6 6 0 0 0 12 3z" }]],
  creds: [["circle", { cx: 8, cy: 15, r: 4 }], ["path", { d: "M11 12l9-9M16 7l3 3M14 9l2 2" }]],
  tarpit: [["path", { d: "M6 3h12M6 21h12M7 3c0 5 5 6 5 9s-5 4-5 9M17 3c0 5-5 6-5 9s5 4 5 9" }]],
  system: [["rect", { x: 6, y: 6, width: 12, height: 12, rx: 2 }], ["rect", { x: 9.5, y: 9.5, width: 5, height: 5 }], ["path", { d: "M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4" }]],
  settings: [["circle", { cx: 12, cy: 12, r: 3 }], ["path", { d: "M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1 7 17M17 7l2.1-2.1" }]],
  look: [["circle", { cx: 12, cy: 12, r: 8.5 }], ["path", { d: "M12 3.5v17a8.5 8.5 0 0 0 0-17z", fill: "currentColor" }]],
  logs: [["path", { d: "M5 4h14v16H5zM8 8h8M8 12h8M8 16h5" }]],
  logout: [["path", { d: "M14 4h5v16h-5M10 8l-4 4 4 4M6 12h10" }]],
  back: [["path", { d: "m15 5-7 7 7 7" }]],
  next: [["path", { d: "m9 5 7 7-7 7" }]],
  expand: [["path", { d: "M14 4h6v6M10 20H4v-6M20 4l-7 7M4 20l7-7" }]],
};
const icon = (k, cls = "tf-ic") => s("svg", { viewBox: "0 0 24 24", "aria-hidden": "true", class: cls }, (ICON[k] || ICON.mehr).map(([t, a]) => s(t, a)));
const NAV_ICON = { "#/": "home", "#/attacks": "attacks", "#/analysis": "analysis", "#/insights": "insights", "#/funde": "funde", "#/creds": "creds", "#/tarpit": "tarpit", "#/system": "system" };
const TAB_HREFS = ["#/", "#/attacks", "#/funde"]; // Tableiste; alles andere steht unter „Mehr“
const TAB_LABEL = { "#/": "Übersicht" };

// ---------- Ampel: Regel aus echten Daten (Angriffe der letzten 60 Minuten, ohne eigene Tests) ----------
// Rot:  ein Angriff erreichte Stufe 3 oder 4 (Befehle ausgeführt, Datei nachgeladen)
// Gelb: ein Login wurde angenommen (Stufe 2), aber keine Befehle
// Grün: nur Abtasten und abgewiesene Versuche
const AMPEL_MIN = 60;
const AMPEL = {
  ok: ["Alles im Rahmen", "Grün", "Nur Abtasten und abgewiesene Versuche.",
    [["circle", { cx: 18, cy: 18, r: 16 }], ["path", { d: "m11 18.5 5 5 9-10" }]]],
  warn: ["Erhöhte Aufmerksamkeit", "Gelb", "Ein Login wurde angenommen, Befehle gab es aber nicht.",
    [["path", { d: "M18 3 34 31H2z" }], ["path", { d: "M18 13v9M18 26.5v.5" }]]],
  bad: ["Eingebrochen", "Rot", "Ein Angreifer hat Befehle ausgeführt oder eine Datei nachgeladen.",
    [["path", { d: "M11 2h14l9 9v14l-9 9H11L2 25V11z" }], ["path", { d: "m12 12 12 12M24 12 12 24" }]]],
  wait: ["Lage wird geprüft …", "", "", [["circle", { cx: 18, cy: 18, r: 16 }]]],
};
const ampelIcon = (k) => s("svg", { viewBox: "0 0 36 36", "aria-hidden": "true", class: "tf-aic" }, AMPEL[k][3].map(([t, a]) => s(t, a)));

// ---------- „Seit deinem letzten Besuch“: Zeitpunkte nur in diesem Browser ----------
// tfSeen: zuletzt sichtbar benutzt (läuft mit, solange die Seite sichtbar ist).
// tfVisit: Beginn von „seit deinem letzten Besuch“. Ein neuer Besuch beginnt, wenn die Seite
// geladen wird oder nach mehr als 30 Minuten Pause wieder sichtbar wird; dann gilt das letzte tfSeen.
const GAP_MS = 30 * 60e3, MAX_BACK = 30 * 86400e3;
const num = (v) => { const n = Number(v); return Number.isFinite(n) && n > 0 ? n : 0; };
function visitStart() {
  const now = Date.now(), seen = num(store("tfSeen"));
  if (seen && now - seen > GAP_MS) store("tfVisit", String(seen));
  store("tfSeen", String(now));
}
const visitFrom = () => num(store("tfVisit"));
// „heute 19:58 Uhr“, „gestern 19:58 Uhr“, sonst „Di. 18.11., 19:58 Uhr“
function dayClock(ms) {
  const d = new Date(ms), t = new Date(), y = new Date(t.getFullYear(), t.getMonth(), t.getDate() - 1);
  const hm = d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" }) + " Uhr";
  if (d.toDateString() === t.toDateString()) return "heute " + hm;
  if (d.toDateString() === y.toDateString()) return "gestern " + hm;
  return `${d.toLocaleDateString("de-DE", { weekday: "short", day: "numeric", month: "numeric" })}, ${hm}`;
}

// ---------- Zustand des Rahmens ----------
let R = null; // { app, top, ampelBtn, moreTab, sheet, back, timers, onKey, onVis, ampel, opener }

function setAmpel(st, reason, stufen) {
  if (!R) return;
  R.ampel = { st, reason, stufen, t: Date.now() };
  const [title] = AMPEL[st];
  R.ampelBtn.dataset.s = st;
  R.ampelBtn.setAttribute("aria-label", `Lage: ${title}${reason ? ", " + reason : ""}. Regel anzeigen`);
  mount(R.ampelBtn, ampelIcon(st), h("span", { class: "tf-atx" }, h("b", null, title), h("small", null, reason || "")), h("i", { class: "tf-dot", "aria-hidden": "true" }));
}
let ampelAt = 0;
async function pollAmpel(soon = false) {
  if (!R || document.hidden) return;
  if (soon && Date.now() - ampelAt < 15000) return; // Live-Anstöße höchstens alle 15 s
  ampelAt = Date.now();
  const d = await api(`attacks?range=1h&stufe=2,3,4&limit=5`, { noAuthRedirect: true }).catch(() => null);
  if (!R || !d) return;
  const st = d.stufen || [0, 0, 0, 0, 0];
  const top = (d.attacks || []).slice().sort((a, b) => b.stufe - a.stufe || b.last - a.last)[0];
  const k = st[3] + st[4] > 0 ? "bad" : st[2] > 0 ? "warn" : "ok";
  const reason = k === "ok" ? `${fmtNum(st[0] + st[1])} Angriffe in ${AMPEL_MIN} Min, keiner kam herein`
    : top ? `${STUFE[top.stufe]} · ${relTime(top.last)}` : AMPEL[k][2];
  setAmpel(k, reason, st);
}

// ---------- Blatt (Mehr, Ampel-Regel, Karte): am Handy Vollbild, am Desktop ein ruhiges Fenster ----------
function openSheet(title, body, { wide = false, onClose = null } = {}) {
  if (!R) return;
  closeSheet(true);
  R.opener = document.activeElement;
  R.sheetClose = onClose;
  const back = h("button", { type: "button", class: "tf-back", onclick: () => closeSheet() }, icon("back"), "Zurück");
  mount(R.sheet, h("div", { class: "tf-sbar" }, back, h("h2", { id: "tf-sheet-h" }, title)), h("div", { class: "tf-sin" }, body));
  R.sheet.classList.toggle("wide", wide);
  R.sheet.hidden = false;
  R.back.hidden = false;
  document.documentElement.classList.add("tf-lock");
  R.sheet.scrollTop = 0;
  back.focus({ preventScroll: true });
}
function closeSheet(silent = false) {
  if (!R || R.sheet.hidden) return;
  R.sheet.hidden = true;
  R.back.hidden = true;
  mount(R.sheet);
  document.documentElement.classList.remove("tf-lock");
  const fn = R.sheetClose; R.sheetClose = null;
  try { fn?.(); } catch (e) { console.error(e); }
  if (!silent && R.opener?.isConnected) R.opener.focus({ preventScroll: true });
  R.opener = null;
}

function openAmpel() {
  const a = R.ampel || { st: "wait", stufen: null };
  const st = a.stufen || [0, 0, 0, 0, 0];
  const row = (k) => h("div", { class: "tf-arow", "data-s": k, "aria-current": a.st === k ? "true" : null },
    ampelIcon(k), h("span", null, h("b", null, AMPEL[k][1], a.st === k ? " – jetzt" : ""), h("small", null, AMPEL[k][2])));
  const q = a.st === "bad" ? "&stufe=3,4" : a.st === "warn" ? "&stufe=2" : "";
  openSheet(AMPEL[a.st][0], h("div", { class: "tf-stack" },
    h("p", { class: "tf-story" }, `Die Ampel schaut auf die Angriffe der letzten ${AMPEL_MIN} Minuten (ohne eigene Tests) und nur darauf, wie weit der weiteste kam – nicht auf die Menge.`),
    row("bad"), row("warn"), row("ok"),
    h("section", { class: "tf-card" }, h("h3", { class: "tf-h" }, h("span", null, `Letzte ${AMPEL_MIN} Minuten`), h("em", null, a.t ? "Stand " + fmtTime(a.t) : "")),
      h("div", { class: "tf-lv" }, STUFE.map((x, i) => h("div", null, h("span", null, h("i", { class: "tf-dotc", style: { "--c": sevColor(i) } }), x), h("b", { class: "num" }, a.stufen ? fmtNum(st[i]) : "–"))))),
    h("a", { class: "tf-btn brand", href: `#/attacks?range=1h${q}` }, a.st === "ok" ? "Angriffe der letzten Stunde" : "Diese Angriffe ansehen", icon("next")),
    h("p", { class: "muted tf-small" }, "Die Ampel wird jede Minute neu geprüft, solange die Seite offen ist.")));
}

function openMehr(teile) {
  const u = teile.user || {};
  const isAdmin = u.role !== "viewer";
  const here = (location.hash || "#/").split("?")[0];
  const row = (href, label, ic, sub) => h("a", { class: "tf-li" + (here === href || here.startsWith(href + "/") ? " on" : ""), href, "aria-current": here === href ? "page" : null },
    icon(ic), h("span", null, label, sub ? h("small", null, sub) : null), icon("next", "tf-ic tf-chev"));
  const modeSeg = h("div", { class: "tf-seg", role: "group", "aria-label": "Farbmodus" });
  const paintSeg = () => mount(modeSeg, COLOR_MODES.map(([m, l, hint]) => h("button", { type: "button", title: hint, "aria-pressed": String(colorMode() === m),
    onclick: () => { setColorMode(m); paintSeg(); } }, l)));
  paintSeg();
  openSheet("Mehr", h("div", { class: "tf-stack" },
    h("section", { class: "tf-card tf-user" }, h("span", { class: "tf-avatar", "aria-hidden": "true" }, (u.username || "?").slice(0, 1).toUpperCase()),
      h("div", null, h("b", null, u.username || ""), h("div", { class: "muted" }, u.role === "viewer" ? "nur ansehen" : "angemeldet", u.version ? ` · Version ${u.version}` : ""))),
    h("section", { class: "tf-card" }, h("h3", { class: "tf-h" }, h("span", null, "Farbmodus")), modeSeg),
    h("nav", { class: "tf-list", "aria-label": "Weitere Seiten" },
      teile.nav.filter(([href]) => !TAB_HREFS.includes(href)).map(([href, label]) => row(href, label, NAV_ICON[href]))),
    h("div", { class: "tf-list" },
      isAdmin ? row("#/settings", "Einstellungen", "settings") : null,
      row("#/settings/darstellung", "Darstellung", "look", "Theme wechseln"),
      u.logs ? row("#/logs", "Protokolle", "logs") : null,
      h("button", { type: "button", class: "tf-li", onclick: () => { closeSheet(true); teile.logout(); } }, icon("logout"), h("span", null, "Abmelden")))));
}

// ---------- Einhängepunkt: Rahmen ----------
export function shell(app, teile) {
  cleanup();
  const ampelBtn = h("button", { type: "button", class: "tf-ampel", "data-s": "wait", onclick: () => openAmpel() });
  const tab = (href, label) => h("a", { class: "tf-tab", href, "data-navlink": "" }, icon(NAV_ICON[href]), h("span", null, TAB_LABEL[href] || label));
  const moreTab = h("button", { type: "button", class: "tf-tab", "aria-haspopup": "dialog", onclick: () => openMehr(teile) }, icon("mehr"), h("span", null, "Mehr"));
  const tabs = h("nav", { class: "tf-tabs", "aria-label": "Hauptnavigation" },
    h("div", { class: "tf-tabs-in" }, TAB_HREFS.map((href) => tab(href, (teile.nav.find(([x]) => x === href) || [, href])[1])), moreTab));
  const avatar = h("button", { type: "button", class: "tf-avatar", "aria-label": `Benutzer ${teile.user?.username || ""}, Menü Mehr`, onclick: () => openMehr(teile) },
    (teile.user?.username || "?").slice(0, 1).toUpperCase());
  const top = h("div", { class: "top" });
  const main = h("div", { class: "tf-view" });
  const back = h("div", { class: "tf-backdrop", hidden: true, onclick: () => closeSheet() });
  const sheet = h("section", { class: "tf-sheet", role: "dialog", "aria-modal": "true", "aria-labelledby": "tf-sheet-h", hidden: true });
  const root = h("div", { class: "tf-app" },
    h("header", { class: "tf-top" }, h("div", { class: "tf-top-in" }, teile.brand, ampelBtn, tabs, teile.live, avatar)),
    h("main", { class: "tf-main" }, top, main, teile.credit),
    back, sheet);
  mount(app, root);

  const onKey = (e) => { if (e.key === "Escape" && R && !R.sheet.hidden) { e.preventDefault(); closeSheet(); } };
  const onVis = () => {
    if (document.hidden) { store("tfSeen", String(Date.now())); return; }
    visitStart();
    pollAmpel();
  };
  document.addEventListener("keydown", onKey);
  document.addEventListener("visibilitychange", onVis);
  visitStart();
  // Bis an den Rand zeichnen (Notch, Home-Leiste); die sicheren Ränder hält das CSS über env(safe-area-inset-*) frei
  const vp = document.querySelector('meta[name="viewport"]'), vpOld = vp?.getAttribute("content") ?? null;
  if (vp && !/viewport-fit/.test(vpOld || "")) vp.setAttribute("content", `${vpOld}, viewport-fit=cover`);
  R = { app: root, vp, vpOld, top, ampelBtn, moreTab, sheet, back, onKey, onVis, ampel: null, opener: null, sheetClose: null,
    timers: [setInterval(pollAmpel, 60000), setInterval(() => { if (!document.hidden) store("tfSeen", String(Date.now())); }, 60000)] };
  setAmpel("wait", "", null);
  pollAmpel();
  return { main, top };
}

// ---------- Einhängepunkt: Seitenwechsel ----------
export function onRoute({ navHash }) {
  if (!R) return;
  closeSheet(true);
  const base = navHash.split("?")[0].replace(/\/$/, "") || "#";
  const key = base === "#" ? "#/" : base;
  const inTabs = TAB_HREFS.some((x) => (x === "#/" ? key === "#/" : key.startsWith(x)));
  R.moreTab.classList.toggle("on", !inTabs);
  if (!inTabs) R.moreTab.setAttribute("aria-current", "page"); else R.moreTab.removeAttribute("aria-current");
  R.app.classList.toggle("is-dash", key === "#/");
  window.scrollTo(0, 0);
}

// ---------- Einhängepunkt: Aufräumen beim Wechsel auf ein anderes Theme ----------
export function cleanup() {
  if (!R) return;
  closeSheet(true);
  R.timers.forEach(clearInterval);
  document.removeEventListener("keydown", R.onKey);
  document.removeEventListener("visibilitychange", R.onVis);
  document.documentElement.classList.remove("tf-lock");
  if (R.vp && R.vpOld !== null) R.vp.setAttribute("content", R.vpOld);
  R = null;
}

// ---------- Bausteine der Übersicht ----------
const card = (cls, title, em, ...body) => h("section", { class: "tf-card " + cls },
  h("h2", { class: "tf-h" }, h("span", null, title), em ? h("em", null, em) : null), ...body);
const rangeName = (r) => ({ "24h": "24 Std", "7d": "7 Tage", "30d": "30 Tage", "1h": "1 Std" }[r] || r);

function rowBars(box, list, { label, color, href }) {
  const mx = Math.max(1, ...list.map((x) => x[1]));
  mount(box, list.length ? list.map(([k, v]) => h(href ? "a" : "div", { class: "tf-rowbar", href: href ? href(k) : null, style: { "--c": color(k) } },
    h("span", { class: "nm" }, label(k)), h("b", { class: "num" }, fmtNum(v)), h("span", { class: "tr" }, h("i", { style: { width: (v / mx) * 100 + "%" } }))))
    : h("p", { class: "tf-empty" }, "Noch nichts im Zeitraum."));
}

// Verlauf nach Stufe (gestapelt), zeichnet sich in Feldbreite neu
function stufenChart(box) {
  const svg = s("svg", { class: "tf-bars", role: "img", "aria-label": "Angriffe im Zeitraum nach Stufe" });
  box.append(svg);
  let ov = null;
  const fmtAx = (ms, span) => {
    const d = new Date(ms);
    return span > 2 * 86400e3 ? `${d.getDate()}.${d.getMonth() + 1}.` : d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });
  };
  function draw() {
    const W = box.clientWidth, H = 150;
    if (W < 60 || !ov || !ov.hist?.length) { svg.replaceChildren(); return; }
    // auf höchstens 24 Säulen zusammenfassen, damit sie am Handy breit genug bleiben
    const per = Math.max(1, Math.ceil(ov.hist.length / 24)), cols = [];
    for (let i = 0; i < ov.hist.length; i += per) cols.push(ov.hist.slice(i, i + per).reduce((a, c) => a.map((v, j) => v + c[j]), [0, 0, 0, 0, 0]));
    const n = cols.length, step = ov.step * per, span = step * n;
    const tot = cols.map((c) => c.reduce((p, q) => p + q, 0));
    const top = Math.max(3, ...tot);
    const T = 4, B = 18, bw = W / n, y = (v) => T + (H - T - B) * (1 - v / top);
    const k = [];
    cols.forEach((col, i) => {
      let acc = 0;
      col.forEach((v, st) => {
        if (!v) return;
        k.push(s("rect", { x: i * bw + 1.5, width: Math.max(1, bw - 3), y: y(acc + v), height: Math.max(1, y(acc) - y(acc + v) - 1), rx: 2, fill: sevColor(st) }));
        acc += v;
      });
      const hit = s("rect", { x: i * bw, width: bw, y: T, height: H - T - B, fill: "transparent" });
      hoverTip(hit, () => [`${fmtAx(ov.from + i * step, 0)}: ${fmtNum(tot[i])} Angriffe`, col.map((c, j) => (c ? [STUFE[j], fmtNum(c), sevColor(j)] : null)).filter(Boolean)]);
      k.push(hit);
    });
    for (const [i, x, a] of [[0, 2, "start"], [Math.floor(n / 2), W / 2, "middle"], [n - 1, W - 2, "end"]]) k.push(s("text", { class: "ax", x, y: H - 4, "text-anchor": a }, fmtAx(ov.from + i * step, span)));
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.replaceChildren(...k);
  }
  const ro = new ResizeObserver(draw);
  ro.observe(box);
  return { set(v) { ov = v; draw(); }, stop: () => ro.disconnect() };
}

// Zoom per Knopf und mit zwei Fingern: dieselbe Logik wie das Mausrad der Karte (charts.js)
function zoomMap(m, dir, at) {
  const svg = m.el.querySelector("svg");
  if (!svg) return;
  const r = svg.getBoundingClientRect(), [x, y] = at || [r.left + r.width / 2, r.top + r.height / 2];
  svg.dispatchEvent(new WheelEvent("wheel", { deltaY: dir, clientX: x, clientY: y, bubbles: true, cancelable: true }));
}
function pinchable(box, m) {
  const pts = new Map(); let base = 0;
  const dist = () => { const [a, b] = [...pts.values()]; return Math.hypot(a.x - b.x, a.y - b.y); };
  box.addEventListener("pointerdown", (e) => { pts.set(e.pointerId, { x: e.clientX, y: e.clientY }); if (pts.size === 2) base = dist(); }, true);
  box.addEventListener("pointermove", (e) => {
    if (!pts.has(e.pointerId)) return;
    pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pts.size < 2) return;
    e.stopPropagation(); // Verschieben während der Fingergeste aussetzen
    const d = dist(), [a, b] = [...pts.values()], mid = [(a.x + b.x) / 2, (a.y + b.y) / 2];
    if (d > base * 1.15) { zoomMap(m, -1, mid); base = d; } else if (d < base / 1.15) { zoomMap(m, 1, mid); base = d; }
  }, true);
  const end = (e) => { pts.delete(e.pointerId); };
  box.addEventListener("pointerup", end, true);
  box.addEventListener("pointercancel", end, true);
}

// ---------- Einhängepunkt: Übersicht ----------
export async function dashboard(el, ctx, d) {
  const r = d.range;
  const h1 = R?.top.querySelector("h1");
  if (h1) h1.textContent = "Übersicht";
  const stufeOf = new Map(); // IP -> höchste bekannte Stufe (Farbe der Bögen)
  const arcColor = (ip) => (stufeOf.has(ip) ? sevColor(stufeOf.get(ip)) : null);
  let cur = d; // letzter Datenstand (für das Karten-Blatt)

  // ---- Seit deinem letzten Besuch ----
  const hero = h("section", { class: "tf-card tf-hero o1", "aria-labelledby": "tf-hero-h" });
  async function fillHero() {
    const from = visitFrom();
    const now = Date.now();
    const start = from && now - from < MAX_BACK ? from : now - 86400e3;
    const hours = Math.min(720, Math.max(1, Math.ceil((now - start) / 3600e3)));
    const rr = hours + "h";
    const head = h("h2", { class: "tf-h", id: "tf-hero-h" }, h("span", null, "Seit deinem letzten Besuch"),
      h("em", null, from ? `${dayClock(start)} · ${relTime(start)}` : "noch keiner gemerkt · letzte 24 Std"));
    const seen = h("button", { type: "button", class: "tf-btn solid", onclick: () => { store("tfVisit", String(Date.now())); seen.textContent = "Als gesehen markiert ✓"; fillHero(); } }, "Alles gesehen");
    const actions = h("div", { class: "tf-actions" }, seen, h("a", { class: "tf-btn line", href: `#/attacks?range=${rr}` }, "Alle ansehen"));
    if (!hero.firstChild) mount(hero, head, h("p", { class: "tf-hero-p" }, "Lade …"), actions);
    const x = await api(`attacks?range=${rr}&from=${start}&limit=40&overview=1`).catch(() => null);
    if (!ctx.current()) return;
    if (!x) { mount(hero, head, h("p", { class: "tf-hero-p" }, "Gerade nicht abrufbar."), actions); return; }
    const ov = x.overview || { stufen: [0, 0, 0, 0, 0], fields: [] };
    const st = ov.stufen || [0, 0, 0, 0, 0];
    const field = (k) => (ov.fields || []).find((f) => f.key === k);
    const nCC = field("country")?.distinct || 0, nHost = field("host")?.distinct || 0;
    const n = x.matched || 0;
    const notable = (x.attacks || []).slice().sort((a, b) => b.stufe - a.stufe || b.last - a.last).filter((a) => a.stufe >= 2).slice(0, 3);
    mount(hero, head,
      h("div", { class: "tf-big num" }, fmtNum(n)),
      h("p", { class: "tf-hero-p" }, n ? `${n === 1 ? "Angriff" : "Angriffe"} aus ${fmtNum(nCC)} ${nCC === 1 ? "Land" : "Ländern"}` : "Nichts Neues. Ruhige Zeit."),
      h("div", { class: "tf-mini" },
        h("a", { href: `#/attacks?range=${rr}&stufe=2,3,4` }, h("b", { class: "num" }, fmtNum(st[2] + st[3] + st[4])), h("span", null, "Login ok")),
        h("a", { href: `#/attacks?range=${rr}&stufe=3,4` }, h("b", { class: "num" }, fmtNum(st[3] + st[4])), h("span", null, "mit Befehlen")),
        h("a", { href: "#/funde" }, h("b", { class: "num" }, fmtNum(nHost)), h("span", null, "Nachlade-Ziele"))),
      notable.length ? h("div", { class: "tf-nlist" }, notable.map((a) => h("a", { class: "tf-item", href: "#/attacker/" + encodeURIComponent(a.ip), style: { "--c": sevColor(a.stufe) } },
        h("span", { class: "flag tf-flag" }, flag(a.country) || ""),
        h("span", { class: "tf-it" }, h("b", null, `${a.country_name || countryName(a.country)} · ${STUFE[a.stufe]}`), h("span", { class: "muted mono" }, a.ip)),
        h("span", { class: "muted" }, relTime(a.last))))) : null,
      actions);
  }

  // ---- Jetzt ----
  const jetztBody = h("div");
  const live = { n: 0, last: null };
  const lastLine = h("p", { class: "tf-last muted" });
  const paintLast = () => {
    const e = live.last;
    mount(lastLine, e ? ["Zuletzt: ", h("b", null, svcName(e.service)), " von ", flag(e.country) || "", " ", e.city || countryName(e.country), " · ", relTime(e.ts)] : "Noch kein Ereignis seit dem Öffnen.");
  };
  function fillJetzt(dd, act) {
    const ser = dd.ser;
    const a = act ? act.attacks.filter((x) => !x.own) : null;
    const v = Number(ser.totals.connect || 0) + live.n;
    mount(jetztBody,
      h("div", { class: "tf-livenum" }, h("b", { class: "num" }, a ? fmtNum(a.length) : "–"), h("span", { class: "muted" }, "aktive Angreifer (letzte 15 Min)")),
      h("a", { class: "tf-sub", href: `#/attacks?range=${r}` }, h("b", { class: "num tf-conn" }, fmtNum(v)), ` Verbindungen in ${rangeName(r)}`),
      sparkline(ser.series.connect || [], { w: 300, hh: 48 }));
  }

  // ---- Karte (klein) und Karten-Blatt ----
  const map = worldMap(d.mp, { home: d.home, countries: d.countries, arcs: "spur", arcColor, controls: false });
  let big = null; // Karte im Vollbild-Blatt, solange es offen ist
  const nLand = h("em");
  const mapBtn = h("button", { type: "button", class: "tf-mapmini", onclick: () => openMap() }, map.el,
    h("span", { class: "tf-cta", "aria-hidden": "true" }, icon("expand"), "Vergrößern"));
  function openMap() {
    const dd = cur;
    big = worldMap(dd.mp, { home: dd.home, countries: dd.countries, arcs: "spur", arcColor, controls: false });
    big.seedActive([...actList.filter((a) => !a.own)]);
    const box = h("div", { class: "tf-mapbig" }, big.el);
    pinchable(box, big);
    const list = dd.countries.filter((c) => c.key && c.key !== "LAN").slice(0, 50);
    const mx = Math.max(1, ...list.map((c) => Number(c.n)));
    const m = big;
    openSheet("Karte", h("div", { class: "tf-stack" },
      h("p", { class: "muted tf-small" }, `Verbindungen in ${rangeName(r)} aus ${fmtNum(list.length)} Ländern. Mit zwei Fingern oder den Knöpfen zoomen, mit einem Finger verschieben. Neue Angriffe erscheinen als Bogen zum Honeypot, Farbe = Stufe.`),
      box,
      h("div", { class: "tf-zoombar", role: "group", "aria-label": "Zoom" },
        h("button", { type: "button", "aria-label": "Hineinzoomen", onclick: () => zoomMap(m, -1) }, "+"),
        h("button", { type: "button", "aria-label": "Herauszoomen", onclick: () => zoomMap(m, 1) }, "−"),
        ["Welt", "Europa", "Asien"].map((z) => h("button", { type: "button", class: "txt", onclick: () => m.zoom(z) }, z))),
      h("section", { class: "tf-card" }, h("h3", { class: "tf-h" }, h("span", null, "Länder"), h("em", null, "antippen = Angriffe aus diesem Land")),
        h("div", { class: "tf-clist" }, list.length ? list.map((c) => h("a", { class: "tf-rowbar", href: `#/attacks?range=${r}&q=${encodeURIComponent("country:" + c.key)}`, style: { "--c": "var(--accent)" } },
          h("span", { class: "nm" }, h("span", { class: "flag" }, flag(c.key) || ""), c.label || countryName(c.key)), h("b", { class: "num" }, fmtNum(c.n)),
          h("span", { class: "tr" }, h("i", { style: { width: (Number(c.n) / mx) * 100 + "%" } })))) : h("p", { class: "tf-empty" }, "Noch keine Herkunft bekannt.")))),
    { wide: true, onClose: () => { big = null; } });
  }

  // ---- Verlauf, Stufen, Woher, Dienste, Funde ----
  const chartBox = h("div", { class: "tf-chartbox" });
  const chart = stufenChart(chartBox);
  ctx.onCleanup(chart.stop);
  const verlaufEm = h("em");
  const stufenBody = h("div");
  const woherBox = h("div"), svcBox = h("div"), funBody = h("div", null, h("p", { class: "muted" }, "Lade …"));
  const warn = h("div", { class: "tf-warn" });

  function fill(dd) {
    cur = dd;
    mount(warn, warningsBox(dd.sys && dd.sys.warnings, true));
    fillJetzt(dd, lastAct);
    map.setData(dd.mp, dd.countries);
    const nc = dd.countries.filter((c) => c.key && c.key !== "LAN").length;
    nLand.textContent = `${fmtNum(nc)} Länder · ${rangeName(r)}`;
    rowBars(woherBox, dd.countries.filter((c) => c.key && c.key !== "LAN").slice(0, 5).map((c) => [c.key, Number(c.n), c.label]), {
      label: (k) => [h("span", { class: "flag" }, flag(k) || ""), countryName(k)], color: () => "var(--accent)",
      href: (k) => `#/attacks?range=${r}&q=${encodeURIComponent("country:" + k)}` });
    const bySvc = new Map();
    for (const p of dd.ports) bySvc.set(p.label || "other", (bySvc.get(p.label || "other") || 0) + Number(p.n || 0));
    rowBars(svcBox, [...bySvc].sort((a, b) => b[1] - a[1]).slice(0, 5), {
      label: (k) => [h("i", { class: "tf-dotc", style: { "--c": svcColor(k) } }), svcName(k)], color: (k) => svcColor(k),
      href: (k) => `#/attacks?range=${r}&service=${encodeURIComponent(k)}` });
  }
  async function fillExtra() {
    const [ov, fu] = await Promise.all([
      api(`attacks?range=${encodeURIComponent(r)}&limit=1&overview=1`).then((x) => x.overview).catch(() => null),
      api("funde?range=" + encodeURIComponent(/^\d+[hdwm]$/.test(r) ? r : "7d")).catch(() => null),
    ]);
    if (!ctx.current()) return;
    chart.set(ov);
    const st = (ov && ov.stufen) || [0, 0, 0, 0, 0], tot = st.reduce((a, b) => a + b, 0);
    verlaufEm.textContent = `${fmtNum(tot)} Angriffe`;
    mount(stufenBody,
      h("div", { class: "tf-stackbar", role: "img", "aria-label": "Verteilung der Stufen: " + STUFE.map((x, i) => `${x} ${st[i]}`).join(", ") },
        tot ? st.map((v, i) => (v ? h("i", { style: { "--c": sevColor(i), flex: String(v) } }) : null)) : h("i", { class: "none" })),
      h("div", { class: "tf-lv" }, STUFE.map((x, i) => h("a", { href: `#/attacks?range=${r}&stufe=${i}` },
        h("span", null, h("i", { class: "tf-dotc", style: { "--c": sevColor(i) } }), x), h("b", { class: "num" }, fmtNum(st[i]))))));
    const f = fu && fu.funnel;
    if (!f) { mount(funBody, h("p", { class: "muted" }, "Funde gerade nicht abrufbar.")); return; }
    const steps = [["Nachlade-Adressen", f.seen || 0], ["geholt", f.fetched || 0], ["Schadsoftware", f.malware || 0], ["an URLhaus gemeldet", (f.urlhaus_ok || 0) + (f.urlhaus_error || 0)]];
    const mxn = Math.max(1, f.seen || 0);
    mount(funBody, h("div", { class: "tf-lv" }, steps.map(([l, n], i) => h("div", { class: i === 2 && n ? "crit" : null },
      h("span", null, l), h("b", { class: "num" }, fmtNum(n)), h("span", { class: "tr" }, h("i", { style: { width: (n / mxn) * 100 + "%" } }))))),
      h("a", { class: "tf-more", href: "#/funde" }, "Alle Funde", icon("next")));
  }

  const legend = h("div", { class: "tf-legend" }, STUFE_KURZ.map((x, i) => h("span", null, h("i", { class: "tf-dotc", style: { "--c": sevColor(i) } }), x)));
  mount(el, h("div", { class: "tf-dash" },
    warn,
    h("div", { class: "tf-layout" },
      h("div", { class: "tf-col a" },
        hero,
        card("o3", "Woher – auf der Karte", nLand, mapBtn, h("p", { class: "muted tf-small" }, "Neue Angriffe erscheinen als Bogen zum Honeypot und verblassen nach einigen Minuten.")),
        card("o8", "Funde", "Nachladen", funBody)),
      h("div", { class: "tf-col b" },
        card("o2", "Jetzt", h("span", { class: "tf-livetag" }, "live"), jetztBody, lastLine),
        card("o4", "Verlauf", verlaufEm, chartBox, legend),
        card("o5", "Wie weit kamen sie?", rangeName(r), stufenBody),
        card("o6", "Woher", "Verbindungen", woherBox),
        card("o7", "Welche Dienste", "Verbindungen", svcBox)))));
  let lastAct = null, actList = [];
  fill(d);
  paintLast();
  fillExtra();
  fillHero();

  d.actP.then((act) => {
    if (!act || !ctx.current()) return;
    lastAct = act; actList = act.attacks || [];
    for (const a of actList) if (!a.own) stufeOf.set(a.ip, Math.max(stufeOf.get(a.ip) ?? 0, a.stufe));
    map.seedActive(actList.filter((a) => !a.own));
    fillJetzt(cur, act);
  });
  ctx.live((e) => {
    map.track(e);
    big?.track(e);
    if (e.type === "disconnect" || !e.src_ip) return;
    live.last = e;
    paintLast();
    if (e.type === "connect") {
      live.n++;
      const c = jetztBody.querySelector(".tf-conn");
      if (c) c.textContent = fmtNum(Number(cur.ser.totals.connect || 0) + live.n);
    }
  });
  liveAttacks(ctx, (updated) => {
    for (const a of updated) {
      if (a.own) continue;
      stufeOf.set(a.ip, a.stufe);
      map.recolor(a.ip);
      big?.recolor(a.ip);
      const i = actList.findIndex((x) => x.id === a.id);
      if (i >= 0) actList[i] = a; else actList.push(a);
    }
    // die Ampel hört mit: Befehle oder ein angenommener Login färben sie sofort
    const now = Date.now();
    if (updated.some((a) => !a.own && a.stufe >= 2 && now - a.last < ACTIVE_MS)) pollAmpel(true);
  });
  // Daten im Hintergrund auffrischen, ohne die Karte (und ihre Bögen) neu aufzubauen
  ctx.every(60000, async () => {
    if (document.hidden) return;
    try {
      const nd = await loadDashboard(r);
      if (!ctx.current() || state.range !== r) return;
      live.n = 0;
      fill(nd);
      fillExtra();
      fillHero();
      nd.actP.then((act) => { if (act && ctx.current()) { lastAct = act; actList = act.attacks || []; fillJetzt(cur, act); } });
    } catch { /* nächster Versuch */ }
  });
  ctx.every(30000, paintLast);
}
