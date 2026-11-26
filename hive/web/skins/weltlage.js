// Theme „Weltlage“: Die Weltkarte ist die Seite (Entwurf konzepte/themes/3-weltlage.html).
// Einhängepunkte (themes.js): shell (obere Glasleiste, schwebende Navigation unten, Befehlspalette
// mit Strg+K, ruhiger Kartenhintergrund hinter den übrigen Seiten), onRoute (Übersicht oder
// Glas-Panel), dashboard (Karte als Vollbild, darüber Bereiche in Andockzonen), einstellungen
// („Glas aus“, Anordnung zurücksetzen), cleanup.
// Klickwege kommen ausschließlich aus ziele.js: jede Kennzahl, Zeile und jedes Land führt zur
// selben Seite wie im Standard. Kopfzeilen der Bereiche navigieren nie (dort wird gezogen).
// Alle übrigen Seiten bleiben die des Standards und werden nur über skins/weltlage.css angepasst.
import { h, s, mount, api, fmtNum, fmtTime, flag, store, hoverTip, ACTIVE_MS, ACTIVE_TITLE } from "../dom.js";
import { worldMap, svcName, countryName } from "../charts.js";
import { STUFE, STUFE_KURZ, sevColor, liveAttacks } from "../attacks.js";
import { state, loadDashboard, describe, TYPE_NAME, warningsBox, liveStatFns, liveActiveCount } from "../app.js";
import { ziel, zielTitel, ip as ipZiel, land as landZiel, stufe as stufeZiel, fund as fundZiel } from "../ziele.js";
import { COUNTRIES, COUNTRY_NAMES } from "../world.js";

// ---------- Symbole (Linien, 24er Raster) ----------
const ICON = {
  dash: [["path", { d: "M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M3.6 9h16.8M3.6 15h16.8M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" }]],
  attacks: [["circle", { cx: 12, cy: 12, r: 7.5 }], ["circle", { cx: 12, cy: 12, r: 2 }], ["path", { d: "M12 2v5M12 17v5M2 12h5M17 12h5" }]],
  analysis: [["path", { d: "M4 20V10M10 20V4M16 20v-7M21 20H3" }]],
  insights: [["path", { d: "M9 18h6M10 21h4" }], ["path", { d: "M12 3a6 6 0 0 0-3.5 10.9c.6.5 1 1.2 1 2.1h5c0-.9.4-1.6 1-2.1A6 6 0 0 0 12 3z" }]],
  funde: [["path", { d: "M9 3h6M10 3v6l-5.5 9.5A1.5 1.5 0 0 0 5.8 21h12.4a1.5 1.5 0 0 0 1.3-2.5L14 9V3" }], ["path", { d: "M7.5 15h9" }]],
  creds: [["circle", { cx: 8, cy: 15, r: 4 }], ["path", { d: "M11 12l9-9M16 7l3 3M14 9l2 2" }]],
  tarpit: [["path", { d: "M6 3h12M6 21h12M7 3c0 5 5 6 5 9s-5 4-5 9M17 3c0 5-5 6-5 9s5 4 5 9" }]],
  system: [["rect", { x: 6, y: 6, width: 12, height: 12, rx: 2 }], ["rect", { x: 9.5, y: 9.5, width: 5, height: 5 }], ["path", { d: "M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4" }]],
  search: [["circle", { cx: 11, cy: 11, r: 6.5 }], ["path", { d: "M16 16l4.5 4.5" }]],
  layers: [["path", { d: "M12 3l9 5-9 5-9-5 9-5z" }], ["path", { d: "M3 13l9 5 9-5" }]],
  grip: [["path", { d: "M9 6h.01M15 6h.01M9 12h.01M15 12h.01M9 18h.01M15 18h.01" }]],
  chev: [["path", { d: "M6 9l6 6 6-6" }]],
  more: [["path", { d: "M5 12h.01M12 12h.01M19 12h.01" }]],
  mehr: [["path", { d: "M4 7h16M4 12h16M4 17h16" }]],
  check: [["path", { d: "M5 12.5l4.5 4.5L19 7.5" }]],
};
const icon = (k, cls = "wl-i") => s("svg", { viewBox: "0 0 24 24", "aria-hidden": "true", class: cls }, (ICON[k] || ICON.dash).map(([t, a]) => s(t, a)));
const ICON_OF = { "#/": "dash", "#/attacks": "attacks", "#/analysis": "analysis", "#/insights": "insights", "#/funde": "funde", "#/creds": "creds", "#/tarpit": "tarpit", "#/system": "system" };
const NAV_HANDY = new Set(["#/", "#/attacks", "#/analysis", "#/funde"]); // auf dem Handy direkt in der Leiste, der Rest über „Mehr“

const PANELS = { kpi: "Kennzahlen", ticker: "Live-Ticker", verlauf: "Stufenverlauf", laender: "Top-Länder", angreifer: "Top-Angreifer", funde: "Funde" };
const ZONES = { l: "links", o: "oben", r: "rechts" };
const DEF = () => ({ o: ["kpi"], l: ["ticker", "verlauf"], r: ["laender", "angreifer", "funde"], aus: [], zu: [] });
const handy = () => matchMedia("(max-width: 640px)").matches;

// ---------- Zustand des Rahmens ----------
let R = null; // { app, root, page, topSlot, lage, bereicheBtn, palette, menu, onKey, onDown, timers, teile, dash }
const lage = { stufe: -1, t: 0 };

function renderLage() {
  if (!R) return;
  mount(R.lage, lage.stufe >= 0
    ? [h("span", { class: "wl-mu" }, "Lage 15 Min"), h("b", { style: { "--c": sevColor(lage.stufe) } }, `Stufe ${lage.stufe} · ${STUFE[lage.stufe]}`)]
    : lage.t ? [h("span", { class: "wl-mu" }, "Lage 15 Min"), h("b", { class: "ruhig" }, "ruhig")] : null);
  R.lage.hidden = !lage.t;
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

// Ruhiger Kartenhintergrund hinter den übrigen Seiten: ein einziger Pfad aller Länder, ohne Daten
function stillMap() {
  const d = COUNTRIES.map((c) => c.d).join("");
  return h("div", { class: "wl-bg", "aria-hidden": "true" },
    s("svg", { viewBox: "0 5 360 150", preserveAspectRatio: "xMidYMid slice" }, s("path", { d })));
}

// ---------- Menüs (Bereich, Bereiche) ----------
function closeMenu(focusBack = false) {
  if (!R || !R.menu) return;
  const { el, anchor } = R.menu;
  el.remove();
  anchor?.setAttribute("aria-expanded", "false");
  R.menu = null;
  if (focusBack) anchor?.focus();
}
// items: [{ label, act, disabled, checked }] oder "-" für eine Trennlinie
function openMenu(anchor, title, items) {
  if (!R) return;
  const wasOpen = R.menu && R.menu.anchor === anchor;
  closeMenu();
  if (wasOpen) return;
  const btns = [];
  const el = h("div", { class: "wl-menu", role: "menu", "aria-label": title },
    h("div", { class: "mi" }, title),
    items.map((it) => {
      if (it === "-") return h("hr");
      const b = h("button", {
        type: "button", role: it.checked === undefined ? "menuitem" : "menuitemcheckbox",
        "aria-checked": it.checked === undefined ? null : String(!!it.checked), disabled: !!it.disabled,
        onclick: () => { closeMenu(true); it.act(); },
      }, it.checked === undefined ? null : h("span", { class: "ck" }, icon("check")), it.label);
      btns.push(b);
      return b;
    }));
  el.addEventListener("keydown", (e) => {
    const on = btns.filter((b) => !b.disabled), i = on.indexOf(document.activeElement);
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); closeMenu(true); }
    else if (e.key === "ArrowDown") { e.preventDefault(); on[(i + 1) % on.length]?.focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); on[(i - 1 + on.length) % on.length]?.focus(); }
    else if (e.key === "Tab") closeMenu();
  });
  R.root.append(el);
  const r = anchor.getBoundingClientRect(), w = el.offsetWidth, hh = el.offsetHeight;
  el.style.left = Math.max(8, Math.min(innerWidth - w - 8, r.right - w)) + "px";
  el.style.top = (r.bottom + 6 + hh > innerHeight - 8 ? Math.max(8, r.top - hh - 6) : r.bottom + 6) + "px";
  anchor.setAttribute("aria-expanded", "true");
  R.menu = { el, anchor };
  btns.find((b) => !b.disabled)?.focus();
}

// ---------- Befehlspalette (Strg+K): Seiten, Listen, Länder, IPs, Kartenausschnitte, Bereiche ----------
const IP_RE = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f]*:[0-9a-f:.]+)$/i;
const norm = (x) => String(x || "").toLocaleLowerCase("de-DE").normalize("NFD").replace(/[̀-ͯ]/g, "");

function paletteItems(q) {
  const r = state.range || "24h", t = norm(q.trim()), out = [];
  const hit = (...xs) => !t || xs.some((x) => norm(x).includes(t));
  const go = (href) => () => { location.hash = href; };
  const pages = [...R.teile.nav];
  if (R.teile.user && R.teile.user.role !== "viewer") pages.push(["#/settings", "Einstellungen"]);
  pages.push(["#/settings/darstellung", "Darstellung"]);
  if (R.teile.user && R.teile.user.logs) pages.push(["#/logs", "Protokolle"]);
  for (const [href, label] of pages) if (hit(label, "seite")) out.push({ g: "Seite", label, act: go(href) });
  const LISTEN = [["active", "Gerade aktive Angriffe"], ["login", "Login-Versuche"], ["request", "Web-Anfragen"], ["success", "Angriffe mit angenommenem Login"],
    ["fetch", "Angriffe mit Nachladeversuch"], ["creds", "Zugangsdaten"], ["tarpit", "Tarpit"]];
  if (t) for (const [k, label] of LISTEN) if (hit(label)) out.push({ g: "Liste", label, act: go(ziel(k, r)) });
  const raw = q.trim();
  if (IP_RE.test(raw)) out.push({ g: "IP", label: raw, note: "Angreifer-Seite", act: go(ipZiel(raw)) });
  const dash = R.dash;
  if (dash) {
    for (const x of dash.ips()) if (t && x.key.includes(raw) && x.key !== raw) out.push({ g: "IP", label: x.key, note: `${fmtNum(x.n)} Verbindungen`, act: go(ipZiel(x.key)) });
    for (const name of dash.regions()) if (hit(name, "karte")) out.push({ g: "Karte", label: name, note: "Ausschnitt", act: () => dash.zoom(name) });
    for (const id of dash.hidden()) if (hit(PANELS[id], "bereich")) out.push({ g: "Bereich", label: PANELS[id] + " einblenden", act: () => dash.show(id) });
  }
  const top = dash ? dash.countries() : [];
  const lands = t ? Object.entries(COUNTRY_NAMES).filter(([cc, name]) => norm(cc) === t || norm(name).includes(t)).slice(0, 8).map(([cc]) => cc)
    : top.slice(0, 5).map((c) => c.key).filter((cc) => cc && cc !== "LAN");
  for (const cc of lands) {
    const n = top.find((c) => c.key === cc);
    out.push({ g: "Land", label: [flag(cc), " ", countryName(cc)], note: n ? `${fmtNum(n.n)} Verbindungen` : "Angriffe", act: go(landZiel(cc, r)) });
  }
  return out.slice(0, 40);
}

function openPalette() {
  if (!R) return;
  closeMenu();
  if (R.palette) { R.palette.input.focus(); return; }
  const back = document.activeElement;
  const input = h("input", { type: "text", placeholder: "Seite, Land, IP oder Kartenausschnitt …", "aria-label": "Suchen", autocomplete: "off", spellcheck: "false",
    role: "combobox", "aria-expanded": "true", "aria-controls": "wl-pal-list" });
  const list = h("ul", { id: "wl-pal-list", role: "listbox", "aria-label": "Treffer" });
  let items = [], sel = 0;
  const render = () => {
    items = paletteItems(input.value);
    sel = Math.min(sel, Math.max(0, items.length - 1));
    mount(list, items.length ? items.map((it, i) => h("li", {
      role: "option", id: "wl-pal-" + i, "aria-selected": String(i === sel),
      onclick: () => run(i), onmousemove: () => { if (sel !== i) { sel = i; mark(); } },
    }, h("span", { class: "g" }, it.g), h("span", { class: "l" }, it.label), it.note ? h("small", null, it.note) : null))
      : h("li", { class: "leer", role: "presentation" }, "Nichts gefunden. Länder auf Deutsch oder als Kürzel (DE), IPs vollständig."));
    mark();
  };
  const mark = () => {
    list.querySelectorAll("li[role=option]").forEach((li, i) => li.setAttribute("aria-selected", String(i === sel)));
    const cur = list.children[sel];
    if (cur && items.length) { input.setAttribute("aria-activedescendant", cur.id); cur.scrollIntoView({ block: "nearest" }); }
  };
  const close = (focus = true) => {
    if (!R || !R.palette) return;
    R.palette.wrap.remove();
    R.palette = null;
    if (focus && back && back.isConnected) back.focus();
  };
  const run = (i) => { const it = items[i]; if (!it) return; close(false); it.act(); };
  input.addEventListener("input", () => { sel = 0; render(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); sel = Math.min(items.length - 1, sel + 1); mark(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); sel = Math.max(0, sel - 1); mark(); }
    else if (e.key === "Enter") { e.preventDefault(); run(sel); }
    else if (e.key === "Escape") { e.preventDefault(); close(); }
  });
  const wrap = h("div", { class: "wl-palwrap", onclick: (e) => { if (e.target === wrap) close(); } },
    h("div", { class: "wl-pal", role: "dialog", "aria-modal": "true", "aria-label": "Befehlspalette" }, input, list,
      h("div", { class: "foot" }, h("span", null, h("kbd", null, "↑"), h("kbd", null, "↓"), " wählen"), h("span", null, h("kbd", null, "Enter"), " öffnen"), h("span", null, h("kbd", null, "Esc"), " schließen"))));
  R.root.append(wrap);
  R.palette = { wrap, input, close };
  render();
  input.focus();
}

// ---------- Glas aus (deckende Bereiche) ----------
const glasAus = () => store("wlGlas") === "aus";
const applyGlas = () => document.documentElement.classList.toggle("wl-solid", glasAus());

// ---------- Einhängepunkt: Rahmen ----------
export function shell(app, teile) {
  cleanup();
  applyGlas();
  const top = h("div", { class: "top" });
  const main = h("div", { class: "wl-view" });
  const lageEl = h("a", { class: "wl-lage wl-gl", href: ziel("active"), title: `${zielTitel("active")} (${ACTIVE_TITLE})`, hidden: true });
  const bereicheBtn = h("button", { type: "button", class: "wl-tb wl-only-dash", "aria-haspopup": "menu", "aria-expanded": "false", title: "Ausgeblendete Bereiche zurückholen, Anordnung zurücksetzen",
    onclick: (e) => { e.stopPropagation(); R?.dash?.bereicheMenu(bereicheBtn); } }, icon("layers"), h("span", { class: "wl-tl" }, "Bereiche"));
  const sucheBtn = h("button", { type: "button", class: "wl-tb", title: "Befehlspalette: Seiten, Länder, IPs (Strg+K)", onclick: (e) => { e.stopPropagation(); openPalette(); } },
    icon("search"), h("span", { class: "wl-tl" }, "Suchen"), h("kbd", { class: "wl-tl" }, "Strg K"));
  const topSlot = h("div", { class: "wl-topslot wl-gl" });
  const bar = h("header", { class: "wl-topbar" },
    h("div", { class: "wl-pill wl-gl" }, teile.brand, teile.live),
    lageEl,
    topSlot,
    h("span", { class: "sp" }),
    h("div", { class: "wl-tools wl-gl" }, bereicheBtn, sucheBtn, teile.userMenu));
  const nav = h("nav", { class: "wl-nav wl-gl", "aria-label": "Hauptnavigation" },
    teile.nav.map(([href, label]) => h("a", { href, "data-navlink": "", class: NAV_HANDY.has(href) ? null : "wl-nav-x", title: label },
      icon(ICON_OF[href] || "dash"), h("span", { class: "wl-nl" }, label))),
    h("span", { class: "div" }),
    h("button", { type: "button", class: "nb", title: "Befehlspalette: Seiten, Länder, IPs (Strg+K)", onclick: (e) => { e.stopPropagation(); openPalette(); } },
      icon("mehr", "wl-i wl-only-handy"), icon("search", "wl-i wl-no-handy"), h("span", { class: "wl-nl" }, h("span", { class: "wl-only-handy" }, "Mehr"), h("span", { class: "wl-no-handy" }, "Suchen"))));
  const page = h("div", { class: "wl-page wl-gl" }, top, main, teile.credit);
  const root = h("div", { class: "wl-app" }, stillMap(), bar, h("main", { class: "wl-main" }, page), nav);
  mount(app, root);

  const onKey = (e) => {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && (e.key === "k" || e.key === "K")) { e.preventDefault(); openPalette(); return; }
    if (e.key === "Escape" && R?.menu) closeMenu(true);
  };
  const onDown = (e) => { if (R?.menu && !R.menu.el.contains(e.target) && !R.menu.anchor.contains(e.target)) closeMenu(); };
  document.addEventListener("keydown", onKey);
  document.addEventListener("pointerdown", onDown);
  R = { app, root, page, top, topSlot, lage: lageEl, bereicheBtn, palette: null, menu: null, onKey, onDown, teile, dash: null,
    timers: [setInterval(pollLage, 120000)] };
  renderLage();
  setTimeout(pollLage, 1500);
  return { main, top };
}

// ---------- Einhängepunkt: Seitenwechsel ----------
export function onRoute({ navHash }) {
  if (!R) return;
  const isDash = (navHash.split("?")[0].replace(/\/$/, "") || "#") === "#";
  R.root.classList.toggle("is-dash", isDash);
  document.documentElement.classList.toggle("wl-dash-on", isDash); // Seite scrollt auf der Übersicht nicht
  closeMenu();
  R.palette?.close(false);
  // Titel und Zeitraum: auf der Übersicht in der oberen Leiste, sonst oben im Glas-Panel
  if (isDash) { if (R.top.parentNode !== R.topSlot) R.topSlot.append(R.top); }
  else if (R.top.parentNode !== R.page) R.page.prepend(R.top);
  window.scrollTo(0, 0);
}

// ---------- Einhängepunkt: Aufräumen beim Wechsel auf ein anderes Theme ----------
export function cleanup() {
  if (!R) return;
  closeMenu();
  R.palette?.close(false);
  R.timers.forEach(clearInterval);
  document.removeEventListener("keydown", R.onKey);
  document.removeEventListener("pointerdown", R.onDown);
  document.documentElement.classList.remove("wl-solid", "wl-dash-on", "wl-sheet-open");
  R = null;
}

// ---------- Einhängepunkt: Einstellungen → Darstellung ----------
export function einstellungen() {
  const cb = h("input", { type: "checkbox", checked: glasAus(), onchange: (e) => { store("wlGlas", e.target.checked ? "aus" : "an"); applyGlas(); } });
  const msg = h("span", { class: "muted", role: "status" });
  return h("div", { class: "wl-opts" },
    h("label", { class: "inline" }, cb, " Glas aus: Bereiche deckend statt durchscheinend (schont schwache Geräte)"),
    h("div", null, h("button", { class: "btn small", type: "button", onclick: () => { store("wlLayout", ""); msg.textContent = " Zurückgesetzt."; } }, "Anordnung der Bereiche zurücksetzen"), msg));
}

// ---------- Anordnung der Bereiche (gemerkt in store("wlLayout")) ----------
function loadLayout() {
  let L = null;
  try { L = JSON.parse(store("wlLayout") || "null"); } catch { L = null; }
  const def = DEF();
  if (!L || typeof L !== "object") return def;
  const seen = new Set(), out = { o: [], l: [], r: [], aus: [], zu: [] };
  for (const z of ["o", "l", "r"]) for (const id of Array.isArray(L[z]) ? L[z] : []) if (PANELS[id] && !seen.has(id)) { seen.add(id); out[z].push(id); }
  for (const z of ["o", "l", "r"]) for (const id of def[z]) if (!seen.has(id)) { seen.add(id); out[z].push(id); } // neue Bereiche an ihren Standardplatz
  for (const k of ["aus", "zu"]) out[k] = (Array.isArray(L[k]) ? L[k] : []).filter((id) => PANELS[id]);
  return out;
}
const saveLayout = (L) => store("wlLayout", JSON.stringify(L));
const zoneOf = (L, id) => ["o", "l", "r"].find((z) => L[z].includes(id));

// Verlauf nach Stufe (gestapelt), zeichnet sich in Feldgröße neu
function stufenChart(box) {
  const svg = s("svg", { class: "wl-chart", role: "img", "aria-label": "Verlauf der Angriffe nach Stufe" });
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
    const L = 34, Rr = 4, T = 6, B = 16, bw = (W - L - Rr) / n, y = (v) => T + (H - T - B) * (1 - v / top);
    const k = [];
    for (let g = 0; g <= 4; g += 2) {
      const v = (top / 4) * g;
      k.push(s("line", { class: "grid", x1: L, x2: W - Rr, y1: y(v), y2: y(v) }), s("text", { x: L - 5, y: y(v) + 3.5, "text-anchor": "end" }, fmtNum(v)));
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
    const per = Math.max(1, Math.ceil(n / Math.max(2, Math.floor((W - L) / 64))));
    for (let i = 0; i < n; i += per) k.push(s("text", { x: L + i * bw, y: H - 3 }, fmtAx(ov.from + i * ov.step, span)));
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.replaceChildren(...k);
  }
  const ro = new ResizeObserver(draw);
  ro.observe(box);
  return { set(v) { ov = v; draw(); }, stop: () => ro.disconnect() };
}

// ---------- Einhängepunkt: Übersicht ----------
export async function dashboard(el, ctx, d) {
  const r = d.range;
  let cur = d; // letzter Datenstand (für die Befehlspalette)
  const stufeOf = new Map(); // IP -> höchste bekannte Stufe (aus "Gerade aktiv" und Live)
  const arcColor = (ip) => (stufeOf.has(ip) ? sevColor(stufeOf.get(ip)) : null);
  const map = worldMap(d.mp, { home: d.home, countries: d.countries, arcs: "spur", arcColor, onCountry: (cc) => { location.hash = landZiel(cc, r); } });
  const live = { connect: null, active: null };

  // ---- Inhalte der Bereiche ----
  const warn = h("div", { class: "wl-warn" });
  const kpiBox = h("div", { class: "wl-kpis" });
  const topUl = h("ul", { class: "wl-rows" }), landUl = h("ul", { class: "wl-rows" }), funBody = h("div", { class: "wl-fun" });
  const chartBox = h("div", { class: "wl-chartbox" });
  const chart = stufenChart(chartBox);
  ctx.onCleanup(chart.stop);
  const legend = h("div", { class: "wl-legend" }, STUFE_KURZ.map((st, i) => h("a", { href: stufeZiel(i, r), title: `Klick zeigt die Angriffe der Stufe „${STUFE[i]}“` },
    h("i", { style: { background: sevColor(i) } }), st)));

  // Ticker
  let tickMin = 0, paused = false;
  const tick = h("ul", { class: "wl-tick", "aria-live": "off" });
  const recent = [];
  const tkItem = (e) => {
    const st = stufeOf.get(e.src_ip) ?? 0;
    return h("li", null, h("a", { class: "wl-tk", href: ipZiel(e.src_ip), title: "Klick zeigt den Angreifer " + e.src_ip, style: { "--c": sevColor(st) } },
      h("time", { class: "num" }, fmtTime(e.ts)),
      h("span", { class: "tk-m" },
        h("span", { class: "tk-1" }, h("span", { class: "mono" }, e.src_ip), " ", flag(e.country), " ", e.city || countryName(e.country) || ""),
        h("span", { class: "tk-2" }, h("b", null, svcName(e.service)), " ", TYPE_NAME[e.type] || e.type, " ", h("span", { class: "wl-mu" }, describe(e)))),
      h("span", { class: "sv" }, STUFE_KURZ[st])));
  };
  const showable = (e) => e.src_ip && e.type !== "disconnect" && e.type !== "client_version" && (stufeOf.get(e.src_ip) ?? 0) >= tickMin;
  const fillTick = () => mount(tick, recent.filter(showable).slice(0, 50).map(tkItem));
  const addTick = (e) => {
    recent.unshift(e);
    if (recent.length > 300) recent.length = 300;
    if (paused || !showable(e)) return;
    tick.prepend(tkItem(e));
    while (tick.children.length > 50) tick.lastChild.remove();
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

  function fill(d) {
    cur = d;
    const { ser } = d;
    mount(warn, warningsBox(d.sys && d.sys.warnings, true));
    const kp = (key, label, cls, sub) => {
      const v = Number(ser.totals[key] || 0), p = Number(ser.prev[key] || 0);
      const delta = p ? Math.round(((v - p) / p) * 100) : null;
      const big = h("span", { class: "big num" }, fmtNum(v));
      if (key === "connect") live.connect = { el: big, n: v };
      return h("a", { class: "wl-kp" + (cls && v ? " " + cls : ""), href: ziel(key, r), title: (p ? `Zeitraum davor: ${fmtNum(p)}. ` : "") + zielTitel(key) },
        h("span", { class: "lbl" }, label), big,
        h("span", { class: "sub" }, sub || "", delta !== null && delta !== 0 ? h("span", { class: delta > 0 ? "up" : "down" }, `${delta > 0 ? "▲" : "▼"} ${Math.abs(delta)} %`) : null));
    };
    const actBig = h("span", { class: "big num" }, "–");
    live.active = actBig;
    mount(kpiBox,
      kp("connect", "Verbindungen"),
      kp("ips", "Angreifer-IPs", "", `${fmtNum(d.countries.length)} Länder`),
      kp("login", "Login-Versuche"),
      kp("request", "Web-Anfragen"),
      kp("success", "Logins angenommen", "warn"),
      kp("fetch", "Nachladeversuche", "crit"),
      h("a", { class: "wl-kp", href: ziel("active", r), title: `${zielTitel("active")} (${ACTIVE_TITLE})` }, h("span", { class: "lbl" }, "Aktiv (15 Min)"), actBig, h("span", { class: "sub" }, "Angreifer")));
    showActive();
    // Top-Angreifer
    const maxIp = d.ips.length ? Number(d.ips[0].n) || 1 : 1;
    mount(topUl, d.ips.length ? d.ips.slice(0, 8).map((x, i) => h("li", null, h("a", { class: "wl-lr", href: ipZiel(x.key), title: "Klick zeigt den Angreifer " + x.key },
      h("span", { class: "rk" }, i + 1), flag(x.label) || h("span"), h("span", { class: "nm mono" }, x.key),
      h("span", { class: "num" }, fmtNum(x.n)),
      h("span", { class: "pip", style: { "--c": stufeOf.has(x.key) ? sevColor(stufeOf.get(x.key)) : "transparent" }, title: stufeOf.has(x.key) ? STUFE[stufeOf.get(x.key)] + " (gerade aktiv)" : null }),
      h("span", { class: "bar" }, h("i", { style: { width: (Number(x.n) / maxIp) * 100 + "%" } })))))
      : h("li", { class: "empty" }, "Keine Angreifer im Zeitraum."));
    // Top-Länder
    const tc = d.countries.filter((c) => c.key && c.key !== "LAN").slice(0, 8), tm = tc.length ? Number(tc[0].n) || 1 : 1;
    mount(landUl, tc.length ? tc.map((c, i) => h("li", null, h("a", { class: "wl-lr", href: landZiel(c.key, r), title: `Klick zeigt die Angriffe aus ${countryName(c.key)}` },
      h("span", { class: "rk" }, i + 1), flag(c.key) || h("span"), h("span", { class: "nm" }, c.label || countryName(c.key)),
      h("span", { class: "num" }, fmtNum(c.n)), h("span"),
      h("span", { class: "bar" }, h("i", { style: { width: (Number(c.n) / tm) * 100 + "%" } })))))
      : h("li", { class: "empty" }, "Noch keine Länder im Zeitraum."));
    map.setData(d.mp, d.countries);
  }
  function showActive() {
    const n = liveActiveCount();
    if (live.active && n !== null && n !== undefined) live.active.textContent = fmtNum(n);
  }
  liveStatFns.add(showActive);
  ctx.onCleanup(() => liveStatFns.delete(showActive));

  async function fillExtra() {
    const [ov, fu] = await Promise.all([
      api(`attacks?range=${encodeURIComponent(r)}&limit=1&overview=1`).then((x) => x.overview).catch(() => null),
      api("funde?range=" + encodeURIComponent(/^\d+[hdwm]$/.test(r) ? r : "7d")).catch(() => null),
    ]);
    if (!ctx.current()) return;
    chart.set(ov);
    const f = fu && fu.funnel;
    if (!f) { mount(funBody, h("p", { class: "wl-mu" }, "Funde gerade nicht abrufbar.")); return; }
    const steps = [["geholt", f.fetched || 0], ["Schadsoftware", f.malware || 0], ["an URLhaus gemeldet", (f.urlhaus_ok || 0) + (f.urlhaus_error || 0)]];
    const mxn = Math.max(1, f.seen || 0);
    const files = (fu.files || []).slice().sort((a, b) => (Number(b.last) || 0) - (Number(a.last) || 0)).slice(0, 4);
    mount(funBody,
      h("a", { class: "wl-funtop", href: ziel("funde", r), title: zielTitel("funde") },
        h("span", { class: "big num" + (f.malware ? " crit" : "") }, fmtNum(f.seen || 0)), h("span", { class: "lbl" }, "Nachlade-Adressen in Befehlen und Downloads"),
        h("span", { class: "fl" }, steps.map(([l, n]) => h("span", { class: "st" }, h("span", null, l), h("b", { class: "num" }, fmtNum(n)), h("span", { class: "meter" }, h("i", { style: { width: (n / mxn) * 100 + "%" } })))))),
      files.length ? h("ul", { class: "wl-rows wl-files" }, files.map((x) => h("li", null, h("a", { class: "wl-file", href: fundZiel(x.sha256), title: "Klick zeigt die Fallakte dieser Datei" },
        h("span", { class: "nm" }, x.name || "(ohne Namen)"), h("span", { class: "wl-mu" }, [x.type, x.arch].filter(Boolean).join(" · ") || x.sha256.slice(0, 12)),
        x.malware ? h("span", { class: "tag" }, "Schadsoftware") : null)))) : null,
      h("a", { class: "wl-more", href: ziel("funde", r), title: zielTitel("funde") }, "Alle Funde und Fallakten →"));
  }

  // ---- Bereiche bauen ----
  const BODY = {
    kpi: () => [warn, kpiBox],
    ticker: () => [h("div", { class: "wl-tkbar" }, tkSeg, h("span", { class: "sp" }), pauseBtn), tick,
      h("a", { class: "wl-more", href: ziel("attacks", r), title: zielTitel("attacks") }, "Alle Angriffe →")],
    verlauf: () => [chartBox, legend],
    laender: () => landUl,
    angreifer: () => topUl,
    funde: () => funBody,
  };
  const HINT = { laender: "Verbindungen", angreifer: "Verbindungen", funde: "Nachladen", verlauf: "nach Stufe" };
  let L = loadLayout();
  const status = h("div", { class: "wl-vh", role: "status", "aria-live": "polite" });
  const say = (t) => { status.textContent = t; };
  const zoneEl = { o: h("div", { class: "wl-dock wl-dock-o", "data-zone": "o" }), l: h("div", { class: "wl-dock wl-dock-l", "data-zone": "l" }), r: h("div", { class: "wl-dock wl-dock-r", "data-zone": "r" }) };
  const handle = h("button", { type: "button", class: "wl-handle", "aria-expanded": "false", "aria-label": "Bereiche aufklappen", onclick: () => {
    const open = document.documentElement.classList.toggle("wl-sheet-open");
    handle.setAttribute("aria-expanded", String(open));
    handle.setAttribute("aria-label", open ? "Bereiche zuklappen" : "Bereiche aufklappen");
  } });
  const docks = h("div", { class: "wl-docks" }, handle, zoneEl.l, zoneEl.o, zoneEl.r, status);
  ctx.onCleanup(() => document.documentElement.classList.remove("wl-sheet-open"));

  const P = {}; // id -> { el, chev, grip, more }
  for (const id of Object.keys(PANELS)) {
    const hid = "wl-h-" + id;
    const chev = h("button", { type: "button", class: "wl-gbtn", "aria-expanded": "true", title: "Einklappen", onclick: () => toggleCollapse(id) }, icon("chev", "wl-i chev"));
    const more = h("button", { type: "button", class: "wl-gbtn", "aria-haspopup": "menu", "aria-expanded": "false", title: "Andocken, Reihenfolge, Ausblenden", "aria-label": `Menü des Bereichs „${PANELS[id]}“`,
      onclick: (e) => { e.stopPropagation(); panelMenu(id, more); } }, icon("more"));
    const grip = h("button", { type: "button", class: "wl-grip", "aria-label": `Bereich „${PANELS[id]}“ verschieben: Pfeiltasten links, rechts, hoch, runter`, title: "Ziehen zum Verschieben (oder Pfeiltasten)",
      onkeydown: (e) => keyMove(e, id) }, icon("grip"));
    const gh = h("div", { class: "wl-gh" }, grip, h("h2", { id: hid }, PANELS[id]), h("span", { class: "sp" }), HINT[id] ? h("span", { class: "hint" }, HINT[id]) : null, chev, more);
    gh.addEventListener("pointerdown", (e) => startDrag(e, id));
    const body = h("div", { class: "wl-gb", id: "wl-b-" + id }, BODY[id]());
    chev.setAttribute("aria-controls", body.id);
    const el = h("section", { class: "wl-gp wl-gl wl-p-" + id, "aria-labelledby": hid, "data-id": id }, gh, h("div", { class: "wl-gbw" }, body));
    P[id] = { el, chev, grip, more };
  }

  function place() {
    for (const z of ["o", "l", "r"]) zoneEl[z].append(...L[z].map((id) => P[id].el));
    for (const id of Object.keys(P)) {
      const zu = L.zu.includes(id);
      P[id].el.hidden = L.aus.includes(id);
      P[id].el.classList.toggle("collapsed", zu);
      P[id].chev.setAttribute("aria-expanded", String(!zu));
      P[id].chev.title = zu ? "Aufklappen" : "Einklappen";
      P[id].chev.setAttribute("aria-label", `${PANELS[id]} ${zu ? "aufklappen" : "einklappen"}`);
    }
    for (const z of ["o", "l", "r"]) zoneEl[z].classList.toggle("leer", !L[z].some((id) => !L.aus.includes(id)));
  }
  const commit = () => { saveLayout(L); place(); };
  function toggleCollapse(id) {
    L.zu = L.zu.includes(id) ? L.zu.filter((x) => x !== id) : [...L.zu, id];
    commit();
  }
  function moveTo(id, zone, index = null) {
    for (const z of ["o", "l", "r"]) L[z] = L[z].filter((x) => x !== id);
    const list = L[zone];
    list.splice(index === null ? list.length : Math.max(0, Math.min(list.length, index)), 0, id);
    commit();
  }
  function shift(id, dir) {
    const z = zoneOf(L, id), list = L[z], i = list.indexOf(id), j = i + dir;
    if (j < 0 || j >= list.length) return false;
    [list[i], list[j]] = [list[j], list[i]];
    commit();
    return true;
  }
  function hide(id) {
    if (!L.aus.includes(id)) L.aus = [...L.aus, id];
    commit();
    say(`${PANELS[id]} ausgeblendet. „Bereiche“ oben holt ihn zurück.`);
  }
  function show(id) {
    L.aus = L.aus.filter((x) => x !== id);
    commit();
    P[id].grip.focus();
  }
  function panelMenu(id, anchor) {
    const z = zoneOf(L, id), list = L[z], i = list.indexOf(id), quer = z === "o";
    openMenu(anchor, PANELS[id], [
      { label: "Links andocken", disabled: z === "l", act: () => { moveTo(id, "l"); say(`${PANELS[id]} links angedockt.`); } },
      { label: "Oben andocken", disabled: z === "o", act: () => { moveTo(id, "o"); say(`${PANELS[id]} oben angedockt.`); } },
      { label: "Rechts andocken", disabled: z === "r", act: () => { moveTo(id, "r"); say(`${PANELS[id]} rechts angedockt.`); } },
      "-",
      { label: quer ? "Nach links" : "Nach oben", disabled: i <= 0, act: () => shift(id, -1) },
      { label: quer ? "Nach rechts" : "Nach unten", disabled: i >= list.length - 1, act: () => shift(id, 1) },
      { label: L.zu.includes(id) ? "Aufklappen" : "Einklappen", act: () => toggleCollapse(id) },
      "-",
      { label: "Ausblenden", act: () => hide(id) },
    ]);
  }
  function bereicheMenu(anchor) {
    openMenu(anchor, "Bereiche", [
      ...Object.keys(PANELS).map((id) => ({ label: PANELS[id], checked: !L.aus.includes(id), act: () => (L.aus.includes(id) ? show(id) : hide(id)) })),
      "-",
      { label: "Alle aufklappen", disabled: !L.zu.length, act: () => { L.zu = []; commit(); } },
      { label: "Anordnung zurücksetzen", act: () => { L = DEF(); commit(); say("Anordnung zurückgesetzt."); } },
    ]);
  }
  // Tastatur am Griff: links/rechts wechselt die Zone, hoch/runter die Reihenfolge
  function keyMove(e, id) {
    const z = zoneOf(L, id), order = ["l", "o", "r"];
    let done = false;
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      const nz = order[order.indexOf(z) + (e.key === "ArrowLeft" ? -1 : 1)];
      if (nz) { moveTo(id, nz); say(`${PANELS[id]}: ${ZONES[nz]} angedockt.`); done = true; }
    } else if (e.key === "ArrowUp" || e.key === "ArrowDown") {
      done = shift(id, e.key === "ArrowUp" ? -1 : 1);
      if (done) say(`${PANELS[id]}: Platz ${L[z].indexOf(id) + 1} von ${L[z].length}.`);
    } else return;
    e.preventDefault();
    if (done) P[id].grip.focus();
  }

  // Ziehen an der Kopfzeile (nicht an ihren Knöpfen); auf dem Handy nicht
  function startDrag(e, id) {
    if (e.button !== 0 || handy() || (e.target.closest("button") && !e.target.closest(".wl-grip"))) return;
    const el = P[id].el, sx = e.clientX, sy = e.clientY;
    let lifted = false, slot = null, offX = 0, offY = 0, over = null;
    const gh = e.currentTarget;
    const lift = () => {
      const rc = el.getBoundingClientRect();
      offX = sx - rc.left; offY = sy - rc.top;
      slot = h("div", { class: "wl-slot" });
      slot.style.height = rc.height + "px";
      el.before(slot);
      el.style.width = rc.width + "px";
      el.classList.add("lifted");
      docks.classList.add("arranging");
      lifted = true;
    };
    const zoneAt = (x, y) => ["o", "l", "r"].find((z) => {
      const b = zoneEl[z].getBoundingClientRect();
      return b.width > 0 && x >= b.left - 10 && x <= b.right + 10 && y >= b.top - 10 && y <= b.bottom + 10;
    });
    const move = (ev) => {
      if (!lifted) { if (Math.hypot(ev.clientX - sx, ev.clientY - sy) < 5) return; lift(); }
      el.style.left = ev.clientX - offX + "px";
      el.style.top = ev.clientY - offY + "px";
      over = zoneAt(ev.clientX, ev.clientY) || null;
      docks.dataset.over = over || "";
      if (!over) return;
      const quer = over === "o";
      const kids = [...zoneEl[over].children].filter((c) => c !== el && c !== slot && !c.hidden);
      const before = kids.find((c) => { const b = c.getBoundingClientRect(); return quer ? ev.clientX < b.left + b.width / 2 : ev.clientY < b.top + b.height / 2; });
      if (before) zoneEl[over].insertBefore(slot, before); else zoneEl[over].append(slot);
      slot.style.height = quer ? "" : el.offsetHeight + "px";
    };
    const end = (ev, cancel = false) => {
      gh.removeEventListener("pointermove", move);
      gh.removeEventListener("pointerup", up);
      gh.removeEventListener("pointercancel", abort);
      document.removeEventListener("keydown", esc, true);
      if (!lifted) return;
      el.classList.remove("lifted");
      el.style.left = el.style.top = el.style.width = "";
      docks.classList.remove("arranging");
      delete docks.dataset.over;
      const zone = slot.parentNode?.dataset.zone;
      if (!cancel && zone) {
        const ids = [...zoneEl[zone].children].filter((c) => c === slot || (c.dataset.id && c !== el)).map((c) => (c === slot ? id : c.dataset.id));
        slot.remove();
        for (const z of ["o", "l", "r"]) L[z] = L[z].filter((x) => x !== id);
        L[zone] = ids;
        commit();
        say(`${PANELS[id]} ${ZONES[zone]} angedockt.`);
      } else { slot.remove(); place(); }
    };
    const up = (ev) => end(ev);
    const abort = (ev) => end(ev, true);
    const esc = (ev) => { if (ev.key === "Escape") { ev.preventDefault(); ev.stopPropagation(); end(ev, true); } };
    gh.setPointerCapture(e.pointerId);
    gh.addEventListener("pointermove", move);
    gh.addEventListener("pointerup", up);
    gh.addEventListener("pointercancel", abort);
    document.addEventListener("keydown", esc, true);
  }

  place();
  const mapctl = map.controls ? h("div", { class: "wl-mapctl wl-gl" }, map.controls) : null;
  mount(el, h("div", { class: "wl-dash" }, h("div", { class: "wl-map" }, map.el), docks, mapctl));
  fill(d);
  fillExtra();

  // Schnittstelle für Rahmen und Befehlspalette
  const dashApi = {
    bereicheMenu, show, zoom: (name) => map.zoom(name),
    regions: () => ["Welt", "Europa", "Asien", "Nordamerika", "Südamerika"],
    hidden: () => L.aus.slice(), ips: () => (cur.ips || []).slice(0, 20), countries: () => cur.countries || [],
  };
  if (R) R.dash = dashApi;
  ctx.onCleanup(() => { if (R && R.dash === dashApi) R.dash = null; closeMenu(); });

  // Ticker mit den letzten Ereignissen vorbelegen, danach live
  api("events?limit=100").then((rows) => {
    if (!ctx.current()) return;
    for (const e of (rows || []).slice().reverse()) recent.unshift(e);
    fillTick();
  }).catch(() => {});

  // Gerade aktiv: Stufen für Farben und Lage, ruhige Bögen der letzten 15 Minuten
  let actList = [];
  d.actP.then((act) => {
    if (!act || !ctx.current()) return;
    actList = act.attacks || [];
    for (const a of actList) if (!a.own) stufeOf.set(a.ip, Math.max(stufeOf.get(a.ip) ?? 0, a.stufe));
    map.seedActive(actList.filter((a) => !a.own));
    setLage(actList);
    if (liveActiveCount() === null && live.active) live.active.textContent = fmtNum(actList.filter((a) => !a.own && Date.now() - a.last < ACTIVE_MS).length);
    fillTick();
  });
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
