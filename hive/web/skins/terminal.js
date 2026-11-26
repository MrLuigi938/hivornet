// Theme „Terminal“: Hivornet als Textkonsole wie htop oder Midnight Commander
// (Entwurf konzepte/themes/2-terminal.html). Einhängepunkte (themes.js): shell (Titelzeile,
// Befehlszeile, Fußzeile mit Tasten, Hilfe), onRoute, dashboard (Textlayout mit Live-Log),
// einstellungen (Farbe und CRT unter Einstellungen → Darstellung), cleanup.
// Alle übrigen Seiten bleiben die des Standards und werden nur über skins/terminal.css angepasst.
// Befehle führen auf die echten Routen: #/attacks?q=… (Suchsprache hive/query.go),
// #/attacker/<ip>, #/funde?f=<sha256>; der Zeitraum ist derselbe wie im Standard.
import { h, mount, api, fmtNum, fmtTime, flag, store, ACTIVE_MS } from "../dom.js";
import { worldMap, svcName, countryName } from "../charts.js";
import { STUFE, STUFE_KURZ, liveAttacks } from "../attacks.js";
import { state, loadDashboard, describe, TYPE_NAME, warningsBox, route } from "../app.js";

// ---------- Zeichen ----------
const SHADE = ["·", "░", "▒", "▓", "█"]; // Stufe 0–4 als Schraffur (auch ohne Farbsehen lesbar)
const SPK = "▁▂▃▄▅▆▇█";
const EIGHTH = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉"];
const FILL = "─".repeat(400), FILLD = "═".repeat(400);
const cut = (t, n) => { t = String(t ?? ""); return t.length > n ? t.slice(0, Math.max(0, n - 1)) + "…" : t; };
const pad = (t, n) => cut(t, n).padEnd(n);
const padL = (t, n) => String(t).padStart(n);
const norm = (t) => String(t || "").toLowerCase().replace(/ä/g, "ae").replace(/ö/g, "oe").replace(/ü/g, "ue").replace(/ß/g, "ss");
const dim = (t) => h("span", { class: "t-d" }, t);
const ln = (...k) => h("div", { class: "ln" }, ...k);
// Text eines Ereignisses (describe liefert Text oder Knoten, hier nur der Text)
const plain = (x) => h("span", null, x).textContent.replace(/\s+/g, " ").trim();

// Balken aus Blockzeichen mit Achtelschritten, Rest in Rahmenfarbe
function bar(v, max, w) {
  const f = max > 0 ? Math.max(0, Math.min(1, v / max)) * w : 0, full = Math.floor(f), part = Math.round((f - full) * 8);
  let on = "█".repeat(full);
  if (part > 0 && full < w) on += part >= 8 ? "█" : EIGHTH[part];
  return [h("span", { class: "t-bf" }, on), h("span", { class: "t-be" }, "░".repeat(Math.max(0, w - on.length)))];
}
// Sparkline aus ▁▂▃▄▅▆▇█, auf n Zeichen zusammengefasst
function spark(vals, n = 16) {
  let v = (vals || []).map(Number);
  if (!v.length) return "▁".repeat(n);
  if (v.length > n) { const k = v.length / n; v = Array.from({ length: n }, (_, i) => v.slice(Math.floor(i * k), Math.floor((i + 1) * k)).reduce((a, b) => a + b, 0)); }
  const mx = Math.max(1, ...v);
  return v.map((x) => (x > 0 ? SPK[Math.min(7, Math.max(1, Math.ceil((x / mx) * 7)))] : "▁")).join("");
}
const stTag = (st, w = 12) => (st >= 0 ? h("span", { class: "t-st ts" + st, title: STUFE[st] + " (gerade aktiv)" }, pad(`[${st}] ${STUFE_KURZ[st].toUpperCase()}`, w)) : h("span", { class: "t-st" }, " ".repeat(w)));

// Kasten mit Titel in der Rahmenzeile: ┌─ TITEL ──── rechts ─┐, Seiten aus │ (CSS, --t-rail)
function box(title, body, o = {}) {
  const d = !!o.dbl;
  return h("section", { class: "t-box" + (d ? " dbl" : "") + (o.cls ? " " + o.cls : "") },
    h("div", { class: "bt" }, h("span", { "aria-hidden": "true" }, d ? "╔═ " : "┌─ "), h("h2", { class: "ttl" }, title), h("span", { "aria-hidden": "true" }, " "),
      h("span", { class: "fill", "aria-hidden": "true" }, d ? FILLD : FILL), o.right ? h("span", { class: "rt" }, " ", o.right, " ") : null,
      h("span", { "aria-hidden": "true" }, d ? "═╗" : "─┐")),
    h("div", { class: "bm" + (o.scroll ? " scroll" : "") }, body),
    h("div", { class: "bb", "aria-hidden": "true" }, h("span", null, d ? "╚" : "└"), h("span", { class: "fill" }, d ? FILLD : FILL), h("span", null, d ? "╝" : "┘")));
}

// Zeichenbreite der Monospace-Schrift, für Textdiagramme in Kastenbreite
let CW = 8.4;
function measure(ref) {
  const m = h("span", { class: "t-measure", "aria-hidden": "true" }, "M".repeat(40));
  ref.append(m);
  CW = m.getBoundingClientRect().width / 40 || CW;
  m.remove();
}
const colsOf = (el) => (el && el.clientWidth ? Math.max(12, Math.floor(el.clientWidth / CW)) : 60);

// ---------- Farbe und CRT (nur dieser Browser) ----------
const FARBEN = { gruen: "Phosphor-Grün", bernstein: "Bernstein" };
const farbe = () => (store("termFarbe") === "bernstein" ? "bernstein" : "gruen");
const crt = () => store("termCrt") !== "0";
const optSync = new Set(); // Bedienelemente unter Einstellungen → Darstellung nachziehen
function look() {
  const r = document.documentElement;
  r.dataset.tfarbe = farbe();
  r.classList.toggle("t-crt", crt());
  for (const fn of optSync) fn();
}
function setFarbe(v, melden) {
  store("termFarbe", v === "bernstein" ? "bernstein" : "gruen");
  look();
  if (melden) say(`Farbe: ${FARBEN[farbe()]}`, "ok");
}
function setCrt(on, melden) {
  store("termCrt", on ? "1" : "0");
  look();
  if (melden) say(`CRT-Effekt (Zeilenraster, Glühen) ${on ? "an" : "aus"}`, "ok");
}
const toggleFarbe = () => setFarbe(farbe() === "gruen" ? "bernstein" : "gruen", true);

// ---------- Zustand des Rahmens ----------
let R = null; // { app, input, msg, help, lage, clock, nav, timers, onKey, pause, hist, hi }
const lage = { stufe: -1, t: 0 };

function say(t, kind = "") {
  if (!R) return;
  R.msg.className = "t-msg" + (kind ? " " + kind : "");
  R.msg.textContent = t;
}
function renderLage() {
  if (!R) return;
  R.lage.textContent = lage.stufe >= 0 ? `LAGE ${SHADE[lage.stufe]} STUFE ${lage.stufe} ${STUFE_KURZ[lage.stufe].toUpperCase()}` : lage.t ? "LAGE: ruhig" : "";
  R.lage.title = lage.stufe >= 0 ? `Höchste Stufe der letzten 15 Minuten: ${STUFE[lage.stufe]}` : "Keine Angriffe in den letzten 15 Minuten";
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

// ---------- Befehlszeile ----------
const CMDS = ["/ip", "/land", "/stufe", "/dienst", "/fund", "/zeit", "/seite", "/farbe", "/crt", "/hilfe", "/suche", "/clear"];
const SEITEN = [["uebersicht", "#/"], ["dashboard", "#/"], ["angriffe", "#/attacks"], ["analyse", "#/analysis"], ["erkenntnisse", "#/insights"],
  ["funde", "#/funde"], ["zugangsdaten", "#/creds"], ["tarpit", "#/tarpit"], ["system", "#/system"], ["einstellungen", "#/settings"],
  ["darstellung", "#/settings/darstellung"], ["protokolle", "#/logs"], ["ereignisse", "#/feed"], ["feed", "#/feed"], ["sitzungen", "#/sessions"]];
const RANGE_MAX = { h: 9999, d: 1095, w: 156, m: 36 };

function go(hash) {
  if ((location.hash || "#/") === hash) route(); else location.hash = hash;
}
const rangeText = (v) => {
  const m = /^(\d+)([hdwm])$/.exec(v || "");
  if (!m) return v || "";
  const n = Number(m[1]);
  return n + " " + { h: "Std", d: n === 1 ? "Tag" : "Tage", w: n === 1 ? "Woche" : "Wochen", m: n === 1 ? "Monat" : "Monate" }[m[2]];
};

// Suche der Seite Angriffe um einen Feldfilter ergänzen. Auf der Seite Angriffe bleiben die
// übrigen Filter stehen, ein Filter desselben Felds wird ersetzt (leerer token: nur entfernen).
const Q_TOKEN = /-?(?:[a-zäöü]+(?:>=|<=|:|=|<|>))?(?:"[^"]*"|\S+)/gi;
const ALIAS = { country: "country|land", service: "service|dienst|svc", stufe: "stufe", ip: "ip" };
function attHash(field, token) {
  const cur = /^#\/attacks(?:\?(.*))?$/.exec(location.hash || "");
  const p = new URLSearchParams(cur ? cur[1] || "" : "");
  const re = new RegExp(`^-?(?:${ALIAS[field]})(?:>=|<=|:|=|<|>)`, "i");
  const q = ((p.get("q") || "").match(Q_TOKEN) || []).filter((t) => !re.test(t));
  if (token) q.push(token);
  if (field === "stufe") p.delete("stufe");
  if (q.length) p.set("q", q.join(" ")); else p.delete("q");
  const qs = p.toString();
  return "#/attacks" + (qs ? "?" + qs : "");
}
const quote = (v) => (/\s/.test(v) ? `"${v.replace(/"/g, "")}"` : v);

function zeit(arg) {
  const a = norm(arg).replace(/\s+/g, "");
  const FEST = { "24h": "24h", "24std": "24h", "1tag": "24h", "7d": "7d", "7tage": "7d", "1w": "7d", "30d": "30d", "30tage": "30d" };
  const UNIT = { h: "h", std: "h", stunden: "h", d: "d", t: "d", tag: "d", tage: "d", w: "w", woche: "w", wochen: "w", m: "m", monat: "m", monate: "m" };
  let v = FEST[a];
  if (!v) {
    const m = /^([1-9]\d{0,3})([a-z]+)$/.exec(a);
    if (m && UNIT[m[2]]) v = Math.min(Number(m[1]), RANGE_MAX[UNIT[m[2]]]) + UNIT[m[2]];
  }
  if (!v) return say("Aufruf: /zeit 24h | 7d | 30d oder ein eigener Zeitraum wie 12h, 2w (Wochen), 3m (Monate)", "err");
  state.range = v;
  store("range", v);
  store("attRange", v); // auch die Seite Angriffe
  const m = /^#\/attacks\?(.*)$/.exec(location.hash || "");
  const p = m ? new URLSearchParams(m[1]) : null;
  if (p && p.has("range")) { p.set("range", v); go("#/attacks?" + p); } else route();
  say(`Zeitraum: letzte ${rangeText(v)}`, "ok");
}

async function fund(arg) {
  if (!arg) { go("#/funde"); return say("Funde: Was Angreifer nachladen wollten", "ok"); }
  const q = arg.toLowerCase();
  say(`Suche Fund „${arg}“ …`);
  const d = await api("funde?range=30d").catch(() => null);
  if (!d) return say("Funde gerade nicht abrufbar.", "err");
  const files = d.files || [];
  const f = files.find((x) => (x.sha256 || "").startsWith(q)) ||
    files.find((x) => [x.name, x.type, x.arch, (x.patterns || []).join(" "), (x.sources || []).join(" ")].join(" ").toLowerCase().includes(q));
  if (!f) return say(`Kein Fund der letzten 30 Tage passt zu „${arg}“. /fund ohne Text öffnet die Funde.`, "err");
  go("#/funde?f=" + encodeURIComponent(f.sha256));
  say(`Fallakte ${f.name || f.sha256.slice(0, 16)}`, "ok");
}

function run(line) {
  line = String(line || "").trim();
  if (!line) return;
  if (!line.startsWith("/")) { go("#/attacks?" + new URLSearchParams({ q: line })); return say(`Suche „${line}“ in den Angriffen`, "ok"); }
  const [c0, ...rest] = line.split(/\s+/), c = c0.toLowerCase(), arg = rest.join(" ").trim();
  switch (c) {
    case "/ip": {
      const ip = arg.replace(/\*$/, "");
      if (!ip || !/^[0-9a-f.:]+$/i.test(ip)) return say("Aufruf: /ip 1.2.3.4 öffnet das Profil, ein Anfang wie /ip 203.0. filtert die Angriffe", "err");
      const voll = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) || (ip.includes(":") && (ip.includes("::") || ip.split(":").length === 8));
      if (voll && !arg.endsWith("*")) { go("#/attacker/" + encodeURIComponent(ip)); return say(`Profil von ${ip}`, "ok"); }
      go(attHash("ip", `ip:${ip}*`));
      return say(`Angriffe von Adressen, die mit ${ip} beginnen`, "ok");
    }
    case "/land": {
      if (!arg) return say("Aufruf: /land CN (Ländercode) oder /land China", "err");
      const cc = /^[a-z]{2}$/i.test(arg) ? arg.toUpperCase() : null;
      go(attHash("country", "country:" + (cc || quote(arg))));
      return say(cc ? `Angriffe aus ${countryName(cc)} (${cc})` : `Angriffe aus „${arg}“`, "ok");
    }
    case "/stufe": {
      if (!/^[0-4]$/.test(arg)) return say("Aufruf: /stufe 0 bis 4 zeigt Angriffe ab dieser Stufe", "err");
      const n = Number(arg);
      go(attHash("stufe", n ? "stufe>=" + n : ""));
      return say(n ? `Angriffe ab Stufe ${n} (${STUFE[n]})` : "Angriffe aller Stufen", "ok");
    }
    case "/dienst": {
      const sv = arg.toLowerCase();
      if (!/^[a-z0-9-]{1,30}$/.test(sv)) return say("Aufruf: /dienst ssh (auch telnet, http, redis …)", "err");
      go(attHash("service", "service:" + sv));
      return say(`Angriffe auf ${svcName(sv)}`, "ok");
    }
    case "/suche":
      if (!arg) return say("Aufruf: /suche text (Freitext geht auch ohne /suche)", "err");
      go("#/attacks?" + new URLSearchParams({ q: arg }));
      return say(`Suche „${arg}“ in den Angriffen`, "ok");
    case "/clear":
      go("#/attacks");
      return say("Filter gelöscht", "ok");
    case "/fund": return fund(arg);
    case "/zeit": return zeit(arg);
    case "/seite": {
      const a = norm(arg);
      const s = a && (SEITEN.find(([n]) => n === a) || SEITEN.find(([n]) => n.startsWith(a)));
      if (!s) return say("Unbekannte Seite. Möglich: " + SEITEN.map(([n]) => n).join(", "), "err");
      go(s[1]);
      return say("Seite " + s[0], "ok");
    }
    case "/farbe": {
      const a = norm(arg);
      if (!a) return toggleFarbe();
      if (a.startsWith("gr")) return setFarbe("gruen", true);
      if (a.startsWith("be") || a === "amber") return setFarbe("bernstein", true);
      return say("Aufruf: /farbe gruen | bernstein", "err");
    }
    case "/crt": {
      const a = arg.toLowerCase();
      if (a && !["an", "ein", "aus"].includes(a)) return say("Aufruf: /crt an | aus", "err");
      return setCrt(a ? a !== "aus" : !crt(), true);
    }
    case "/hilfe": case "/help": case "/?":
      return help(true);
  }
  say(`Unbekannter Befehl ${c0}. /hilfe zeigt alle Befehle.`, "err");
}

// ---------- Hilfe (F1, Taste 1 oder ?) ----------
function helpBody() {
  const row = (a, b) => h("div", { class: "t-hrow" }, h("span", null, a), h("span", null, b));
  return [
    box("HILFE · TASTEN", [
      row("1 … 9, 0", "Seite wechseln wie in der Fußzeile (auch F1–F4, F6–F10; F5 lädt neu)"),
      row("/", "in die Befehlszeile springen; Esc verlässt sie"),
      row("Tab · ↑ ↓", "Befehl ergänzen · frühere Eingaben"),
      row("? oder H", "diese Hilfe; Esc schließt sie"),
      row("F oder 0", "Farbe: Phosphor-Grün oder Bernstein"),
      row("C", "CRT-Effekt (Zeilenraster, Glühen) an oder aus"),
      row("P (Übersicht)", "Live-Log anhalten und fortsetzen"),
    ], { dbl: true }),
    box("HILFE · BEFEHLE", [
      row("/ip 1.2.3.4", "Profil der Adresse; ein Anfang (/ip 203.0.) filtert die Angriffe"),
      row("/land CN", "Angriffe aus einem Land (Kürzel oder Name)"),
      row("/stufe 3", "Angriffe ab Stufe 3 (0 bis 4)"),
      row("/dienst ssh", "Angriffe auf einen Dienst"),
      row("/fund sora", "Fallakte einer Datei (Name, Hash-Anfang, Typ); ohne Text: Funde"),
      row("/zeit 7d", "Zeitraum: 24h, 7d, 30d oder eigener wie 12h, 2w, 3m"),
      row("/seite angriffe", "Seite öffnen: " + SEITEN.map(([n]) => n).filter((n) => n !== "dashboard" && n !== "feed").join(", ")),
      row("/farbe bernstein", "Farbe: gruen oder bernstein"),
      row("/crt aus", "Zeilenraster und Glühen an oder aus"),
      row("/clear", "Filter der Seite Angriffe löschen"),
      row("Text ohne /", "Suche in den Angriffen, auch mit Feldern wie service:ssh stufe>=3"),
      row("", "/ip, /land, /stufe und /dienst ergänzen auf der Seite Angriffe die vorhandene Suche."),
    ], { dbl: true }),
  ];
}
function help(show) {
  if (!R) return;
  const on = show === undefined ? R.help.hidden : show;
  if (on && R.help.hidden) {
    R.helpBack = document.activeElement;
    R.help.hidden = false;
    R.help.querySelector("button")?.focus();
  } else if (!on && !R.help.hidden) {
    R.help.hidden = true;
    if (R.helpBack && R.helpBack.isConnected) R.helpBack.focus?.();
  }
}

// Taste n der Fußzeile: 1 Hilfe, 2–9 Seiten, 10 Farbe
function fkey(n) {
  if (!R) return;
  if (n === 1) return help();
  if (n === 10) return toggleFarbe();
  const nav = R.nav[n - 2];
  if (nav) { help(false); go(nav[0]); }
}

// ---------- Einhängepunkt: Rahmen ----------
export function shell(app, teile) {
  cleanup();
  look();
  const top = h("div", { class: "top t-top" });
  const main = h("div", { class: "t-view" });
  const lageEl = h("span", { class: "t-lage", role: "status" });
  const clock = h("span", { class: "t-clock num" });
  const hist = [];
  let hi = -1;
  const input = h("input", { id: "t-cmd", type: "text", autocomplete: "off", spellcheck: "false", autocapitalize: "off", enterkeyhint: "go",
    placeholder: "/ip 1.2.3.4   /land CN   /stufe 3   /hilfe   oder Suchtext",
    "aria-label": "Befehlszeile: Befehl oder Suchtext, /hilfe zeigt alle Befehle" });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { input.value = ""; input.blur(); }
    else if (e.key === "Tab" && input.value.startsWith("/") && !input.value.includes(" ")) {
      const m = CMDS.filter((x) => x.startsWith(input.value.toLowerCase()));
      if (m.length) { e.preventDefault(); input.value = m[0] + " "; if (m.length > 1) say("Möglich: " + m.join("  ")); }
    } else if (e.key === "ArrowUp") { e.preventDefault(); if (hi < hist.length - 1) input.value = hist[++hi]; }
    else if (e.key === "ArrowDown") { e.preventDefault(); input.value = hi > 0 ? hist[--hi] : ((hi = -1), ""); }
  });
  const form = h("form", { class: "t-cmd", role: "search", onsubmit: (e) => {
    e.preventDefault();
    const v = input.value.trim();
    if (v && hist[0] !== v) { hist.unshift(v); hist.length = Math.min(hist.length, 50); }
    hi = -1;
    input.value = "";
    run(v);
  } }, h("label", { for: "t-cmd" }, "hive>"), input, h("span", { class: "keys" }, "Tab ergänzt · ↑ frühere · / springt hierher"));
  const msg = h("div", { class: "t-msg", role: "status", "aria-live": "polite" });

  // Fußzeile wie bei mc: Zahl und Name, anklickbar
  const keys = [[1, "Hilfe", null, () => help()], ...teile.nav.slice(0, 8).map(([href, label], i) => [i + 2, label, href]), [10, "Farbe", null, toggleFarbe]];
  const fk = h("nav", { class: "t-fkeys", "aria-label": "Seiten und Tasten" }, keys.map(([n, label, href, fn]) => {
    const key = n === 10 ? "0" : String(n);
    const attrs = { title: `${label}: Taste ${key}${n !== 5 ? " oder F" + n : ""}`, "aria-keyshortcuts": n !== 5 ? `${key} F${n}` : key };
    const kids = [h("b", { "aria-hidden": "true" }, String(n)), h("span", null, label)];
    return href ? h("a", { ...attrs, href, "data-navlink": "" }, kids) : h("button", { ...attrs, type: "button", onclick: fn }, kids);
  }));

  const helpBox = h("section", { class: "t-help", hidden: true, role: "dialog", "aria-label": "Hilfe: Tasten und Befehle" },
    h("div", { class: "t-help-in" }, helpBody(), h("div", { class: "t-help-ft" }, h("button", { type: "button", class: "t-btn", onclick: () => help(false) }, "[Esc] Schließen"))));

  const root = h("div", { class: "t-app" },
    h("header", { class: "t-head" },
      h("div", { class: "t-title" },
        h("a", { class: "t-brand", href: "#/" }, "HIVORNET"),
        teile.user && teile.user.version ? h("span", { class: "opt" }, teile.user.version) : null,
        h("span", { class: "sp" }), lageEl, teile.live, clock, teile.userMenu),
      form, msg),
    h("main", { class: "t-main", id: "t-main", tabindex: "-1" }, top, main, teile.credit),
    fk, helpBox);
  // Seiten der Kästen aus │ bzw. ║ (content: var(--t-rail) im CSS)
  root.style.setProperty("--t-rail", '"' + "│\\A".repeat(240) + '"');
  root.style.setProperty("--t-rail2", '"' + "║\\A".repeat(240) + '"');
  mount(app, root);

  const tick = () => { clock.textContent = new Date().toLocaleTimeString("de-DE"); };
  tick();
  const onKey = (e) => {
    if (!R || e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey || e.isComposing) return;
    const fn = /^F(\d{1,2})$/.exec(e.key);
    if (fn) { // F5 (neu laden), F11 (Vollbild), F12 (Entwicklerwerkzeuge) bleiben beim Browser
      const n = Number(fn[1]);
      if (n >= 1 && n <= 10 && n !== 5) { e.preventDefault(); fkey(n); }
      return;
    }
    if (e.target.closest?.("input, textarea, select, [contenteditable], .range-pop")) return;
    if (e.key === "Escape") { if (!R.help.hidden) { e.preventDefault(); help(false); } return; }
    if (e.key === "/") { e.preventDefault(); help(false); input.focus(); input.value = "/"; return; }
    if (e.key === "?") { e.preventDefault(); help(); return; }
    if (/^[0-9]$/.test(e.key)) { e.preventDefault(); fkey(e.key === "0" ? 10 : Number(e.key)); return; }
    const k = e.key.toLowerCase();
    if (k === "h") { e.preventDefault(); help(); }
    else if (k === "f") { e.preventDefault(); toggleFarbe(); }
    else if (k === "c") { e.preventDefault(); setCrt(!crt(), true); }
    else if (k === "p" && R.pause) { e.preventDefault(); R.pause(); }
  };
  document.addEventListener("keydown", onKey);
  R = { app: root, input, msg, help: helpBox, helpBack: null, lage: lageEl, clock, nav: teile.nav, onKey, pause: null,
    timers: [setInterval(tick, 1000), setInterval(pollLage, 120000)] };
  renderLage();
  setTimeout(pollLage, 1500);
  say("Willkommen. 1 oder ? zeigt Tasten und Befehle, / öffnet die Befehlszeile.");
  return { main, top };
}

// ---------- Einhängepunkt: Seitenwechsel ----------
export function onRoute({ navHash }) {
  if (!R) return;
  const base = navHash.split("?")[0].replace(/\/$/, "") || "#";
  R.app.classList.toggle("is-dash", base === "#" || base === "#/");
  help(false);
  window.scrollTo(0, 0);
}

// ---------- Einhängepunkt: eigene Einstellungen (Einstellungen → Darstellung) ----------
export function einstellungen() {
  const seg = h("div", { class: "seg", role: "radiogroup", "aria-label": "Farbe des Terminals" },
    Object.entries(FARBEN).map(([v, l]) => h("button", { type: "button", role: "radio", "data-v": v, onclick: () => setFarbe(v) }, l)));
  const cb = h("input", { type: "checkbox", onchange: (e) => setCrt(e.target.checked) });
  let shown = false;
  const sync = () => {
    if (seg.isConnected) shown = true;
    else if (shown) { optSync.delete(sync); return; } // Seite verlassen: abmelden
    seg.querySelectorAll("button").forEach((b) => { const on = b.dataset.v === farbe(); b.classList.toggle("on", on); b.setAttribute("aria-checked", String(on)); });
    cb.checked = crt();
  };
  optSync.add(sync);
  sync();
  return h("div", { class: "t-opts" },
    h("div", { class: "t-opt" }, h("span", { class: "t-optl" }, "Terminal-Farbe"), seg),
    h("label", { class: "inline" }, cb, "CRT-Effekt: feines Zeilenraster und leichtes Glühen"),
    h("div", { class: "help" }, "Auch über die Befehlszeile (/farbe, /crt) und die Tasten F und C. Gibt das System „Bewegung reduzieren“ vor, entfallen Blinken und Aufleuchten."));
}

// ---------- Einhängepunkt: Aufräumen beim Wechsel auf ein anderes Theme ----------
export function cleanup() {
  const r = document.documentElement;
  delete r.dataset.tfarbe;
  r.classList.remove("t-crt");
  optSync.clear();
  if (!R) return;
  R.timers.forEach(clearInterval);
  document.removeEventListener("keydown", R.onKey);
  R = null;
}

// ---------- Übersicht ----------
const fmtAx = (ms, span) => {
  const d = new Date(ms);
  return span > 2 * 86400e3 ? `${d.getDate()}.${d.getMonth() + 1}.` : d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });
};
const stepText = (ms) => (ms >= 86400e3 ? `${Math.round(ms / 86400e3)} Tag${ms >= 2 * 86400e3 ? "e" : ""}` : ms >= 3600e3 ? `${Math.round(ms / 3600e3)} Std` : `${Math.round(ms / 60e3)} Min`);

// Gestapelter Verlauf als Text: Schraffur je Stufe (· ░ ▒ ▓ █), höchste Stufe oben
function stackLines(ov, cols) {
  let d = ov.hist.map((c) => [0, 1, 2, 3, 4].map((k) => Number(c[k] || 0)));
  const avail = Math.max(10, cols - 8);
  const merge = Math.max(1, Math.ceil(d.length / avail));
  if (merge > 1) d = Array.from({ length: Math.ceil(d.length / merge) }, (_, i) => d.slice(i * merge, (i + 1) * merge).reduce((a, b) => a.map((x, k) => x + b[k]), [0, 0, 0, 0, 0]));
  const n = d.length, cw = Math.max(1, Math.min(3, Math.floor(avail / n)));
  const tot = d.map((a) => a.reduce((x, y) => x + y, 0)), top = Math.max(4, Math.ceil(Math.max(...tot) / 4) * 4), ROWS = 8;
  const out = [];
  for (let row = 0; row < ROWS; row++) {
    const v = ((ROWS - row - 0.5) / ROWS) * top;
    const kids = [dim((row === 0 ? padL(fmtNum(top), 6) : row === ROWS / 2 ? padL(fmtNum(top / 2), 6) : "      ") + " "), h("span", { class: "t-l" }, "│")];
    let run = null, txt = "";
    const flush = () => { if (txt) kids.push(h("span", { class: run }, txt)); txt = ""; };
    d.forEach((b, i) => {
      let cum = 0, st = -1;
      if (v <= tot[i]) for (let k = 0; k < 5; k++) { cum += b[k]; if (v <= cum) { st = k; break; } }
      const cell = st < 0 ? " ".repeat(cw) : SHADE[st].repeat(cw > 1 ? cw - 1 : 1) + (cw > 1 ? " " : "");
      const cls = st < 0 ? "x" : "tc" + st;
      if (cls !== run) { flush(); run = cls; }
      txt += cell;
    });
    flush();
    out.push(ln(...kids));
  }
  out.push(ln(dim("       "), h("span", { class: "t-l" }, "└" + "─".repeat(n * cw))));
  const span = ov.step * ov.hist.length, lab = Array(n * cw + 8).fill(" "), every = Math.max(1, Math.ceil((span > 2 * 86400e3 ? 7 : 6) / cw));
  for (let i = 0; i < n; i += every) {
    const t = fmtAx(ov.from + i * merge * ov.step, span);
    for (let j = 0; j < t.length && 8 + i * cw + j < lab.length; j++) lab[8 + i * cw + j] = t[j];
  }
  out.push(ln(dim(lab.join("").trimEnd())));
  out.push(ln(...STUFE_KURZ.flatMap((st, i) => [h("span", { class: "tc" + i }, SHADE[i]), dim(" " + st + "  ")])));
  return { lines: out, step: ov.step * merge };
}

// ---------- Einhängepunkt: Übersicht ----------
export async function dashboard(el, ctx, d0) {
  const r = d0.range;
  let d = d0, ov = null, fu = null;
  const stufeOf = new Map(); // IP -> Stufe (aus "Gerade aktiv" und Live)
  const tone = (st) => (st >= 4 ? "var(--t-hi)" : st >= 2 ? "var(--t-fg)" : "var(--t-dim)");
  const map = worldMap(d.mp, { home: d.home, countries: d.countries, arcs: "spur", arcColor: (ip) => (stufeOf.has(ip) ? tone(stufeOf.get(ip)) : null) });

  const warn = h("div", { class: "t-warn" });
  const kpis = h("div", { class: "t-kpis" });
  const chartEl = h("div", { class: "t-chart", role: "img", "aria-label": "Verlauf der Angriffe nach Stufe" });
  const chartRight = h("span", null, "Angriffe");
  const svcEl = h("div", { class: "t-list" }), topEl = h("div", { class: "t-list" }), landEl = h("div", { class: "t-list" }), funEl = h("div", { class: "t-list" });

  // ---- Live-Log: neueste Zeile unten, folgt, solange ganz unten gelesen wird ----
  const logEl = h("div", { class: "t-log", role: "log", "aria-label": "Live-Feed", "aria-live": "off", tabindex: "0" });
  const buf = [];
  let follow = true, paused = false;
  logEl.addEventListener("scroll", () => { follow = logEl.scrollHeight - logEl.scrollTop - logEl.clientHeight < 30; });
  const showable = (e) => e.src_ip && e.type !== "disconnect" && e.type !== "client_version";
  const lgLine = (e, fresh) => {
    const st = stufeOf.get(e.src_ip) ?? 0;
    const text = `${fmtTime(e.ts)} ${SHADE[st]}${st} ${pad(svcName(e.service || "").toUpperCase(), 6)} ${pad(e.src_ip, 15)} ${pad(e.country || "--", 2)} ${pad(String(TYPE_NAME[e.type] || e.type).toLowerCase(), 10)} ${plain(describe(e))}`;
    return h("a", { class: "lg ts" + st + (fresh ? " new" : ""), href: "#/attacker/" + encodeURIComponent(e.src_ip), title: `${STUFE[st]} · Klick öffnet das Profil von ${e.src_ip}` }, text);
  };
  const toBottom = () => { logEl.scrollTop = logEl.scrollHeight; };
  const fillLog = () => {
    const rows = buf.filter(showable).slice(-200);
    mount(logEl, rows.length ? rows.map((e) => lgLine(e, false)) : h("div", { class: "lg t-d" }, "Warte auf Ereignisse …"));
    toBottom();
    follow = true;
  };
  const addLog = (e) => {
    buf.push(e);
    if (buf.length > 400) buf.splice(0, buf.length - 400);
    if (paused || !showable(e)) return;
    if (logEl.firstChild && !logEl.firstChild.href) logEl.firstChild.remove(); // „Warte …“
    logEl.append(lgLine(e, true));
    while (logEl.children.length > 200) logEl.firstChild.remove();
    if (follow) toBottom();
  };
  const pauseBtn = h("button", { type: "button", class: "t-btn", "aria-pressed": "false", title: "Live-Log anhalten (Taste P)" }, "[P] Pause");
  const togglePause = () => {
    paused = !paused;
    pauseBtn.textContent = paused ? "[P] Weiter" : "[P] Pause";
    pauseBtn.setAttribute("aria-pressed", String(paused));
    if (!paused) fillLog();
    say(paused ? "Live-Log angehalten (P setzt fort)" : "Live-Log läuft", "ok");
  };
  pauseBtn.addEventListener("click", togglePause);
  if (R) R.pause = togglePause;
  ctx.onCleanup(() => { if (R && R.pause === togglePause) R.pause = null; });

  // ---- Felder füllen (auch bei der Aktualisierung) ----
  const live = { connect: null };
  function fillKpis() {
    const { ser } = d;
    const kp = (key, label, href, sub) => {
      const v = Number(ser.totals[key] || 0), p = Number(ser.prev[key] || 0), delta = p ? Math.round(((v - p) / p) * 100) : null;
      const big = h("div", { class: "bg num" }, fmtNum(v));
      if (key === "connect") live.connect = { el: big, n: v };
      return h("a", { class: "t-kp", href, title: (p ? `Zeitraum davor: ${fmtNum(p)}. ` : "") + "Klick zeigt die Liste dazu." },
        h("div", { class: "lb" }, label), big,
        h("div", { class: "sk", "aria-hidden": "true" }, spark(ser.series[key], 16)),
        h("div", { class: "sb" }, sub || "", delta ? `${sub ? " " : ""}${delta > 0 ? "▲" : "▼"}${Math.abs(delta)} %` : ""));
    };
    mount(kpis,
      kp("connect", "Verbindungen", `#/attacks?range=${r}`),
      kp("ips", "Angreifer-IPs", `#/attacks?range=${r}`, `${fmtNum(d.countries.length)} Länder`),
      kp("login", "Login-Versuche", "#/feed?type=login"),
      kp("success", "Login angenommen", `#/attacks?range=${r}&success=1`),
      kp("fetch", "Nachladeversuche", `#/attacks?range=${r}&q=nachladen:ja`));
  }
  // alles, was von der Kastenbreite abhängt
  function layout() {
    if (!el.isConnected) return;
    // Verlauf
    if (ov && ov.hist && ov.hist.length && ov.hist.some((c) => c.some(Number))) {
      const { lines, step } = stackLines(ov, colsOf(chartEl));
      mount(chartEl, lines);
      chartRight.textContent = "Angriffe je " + stepText(step);
      chartEl.setAttribute("aria-label", "Verlauf der Angriffe nach Stufe. Im Zeitraum: " + STUFE.map((s, i) => `${s} ${fmtNum((ov.stufen || [])[i] || 0)}`).join(", "));
    } else mount(chartEl, ln(dim(ov ? "Keine Angriffe im Zeitraum." : "Lade …")));
    // Dienste nach Anteil der Verbindungen
    const bySvc = new Map();
    for (const p of d.ports) bySvc.set(p.label || "other", (bySvc.get(p.label || "other") || 0) + Number(p.n || 0));
    const sv = [...bySvc].sort((a, b) => b[1] - a[1]).slice(0, 8), tot = Math.max(1, sv.reduce((t, [, n]) => t + n, 0)), mx = sv.length ? sv[0][1] : 1;
    const bwS = Math.max(4, colsOf(svcEl) - 11 - 16);
    mount(svcEl, sv.length ? sv.map(([k, n]) => h("a", { class: "ln t-row", href: attHrefFresh("service:" + k), title: `Angriffe auf ${svcName(k)}` },
      pad(svcName(k), 10) + " ", bar(n, mx, bwS), dim(` ${padL(Math.round((n / tot) * 100), 3)} % ${padL(fmtNum(n), 8)}`))) : ln(dim("Noch keine Verbindungen.")));
    // Herkunft nach Land
    const tc = d.countries.slice(0, 8), tm = tc.length ? Number(tc[0].n) : 1;
    const bwL = Math.max(4, colsOf(landEl) - 3 - 3 - 16 - 10);
    mount(landEl, tc.length ? tc.map((c) => h("a", { class: "ln t-row", href: attHrefFresh("country:" + c.key), title: `Angriffe aus ${c.label || countryName(c.key)}` },
      flag(c.key) || " ", " ", pad(c.key, 3), pad(c.label || countryName(c.key), 15) + " ", bar(Number(c.n), tm, bwL), dim(" " + padL(fmtNum(c.n), 8)))) : ln(dim("Keine Herkunft im Zeitraum.")));
    // Funde: Trichter
    const f = fu && fu.funnel;
    if (!f) mount(funEl, ln(dim(fu === null ? "Lade …" : "Funde gerade nicht abrufbar.")));
    else {
      const mxn = Math.max(1, f.seen || 0), bwF = Math.max(4, colsOf(funEl) - 16 - 10);
      const st = (l, n) => ln(pad(l, 15) + " ", bar(n, mxn, bwF), h("span", { class: "num" }, " " + padL(fmtNum(n), 8)));
      mount(funEl, st("Adressen", f.seen || 0), st("geholt", f.fetched || 0), st("Schadsoftware", f.malware || 0),
        st("gemeldet", (f.urlhaus_ok || 0) + (f.urlhaus_error || 0)), h("a", { class: "ln t-row", href: "#/funde" }, "→ Funde und Fallakten"));
    }
  }
  // Top-Angreifer (Stufe nur für gerade aktive bekannt)
  function fillTop() {
    mount(topEl, d.ips.length ? d.ips.slice(0, 8).map((x, i) => h("a", { class: "t-top-row", href: "#/attacker/" + encodeURIComponent(x.key), title: `Profil von ${x.key}` },
      dim(padL(i + 1, 2)), h("span", null, flag(x.label) || pad(x.label || "", 2)), h("span", { class: "ip" }, x.key), h("span", { class: "num" }, padL(fmtNum(x.n), 7)),
      stTag(stufeOf.has(x.key) ? stufeOf.get(x.key) : -1))) : ln(dim("Keine Angreifer im Zeitraum.")));
  }
  function fill() {
    mount(warn, warningsBox(d.sys && d.sys.warnings, true));
    fillKpis();
    fillTop();
    map.setData(d.mp, d.countries);
    layout();
  }
  async function fillExtra() {
    const [o, f] = await Promise.all([
      api(`attacks?range=${encodeURIComponent(r)}&limit=1&overview=1`).then((x) => x.overview).catch(() => null),
      api("funde?range=" + encodeURIComponent(/^\d+[hdwm]$/.test(r) ? r : "7d")).catch(() => false),
    ]);
    if (!ctx.current()) return;
    ov = o || { hist: [] };
    fu = f;
    layout();
  }

  const mapBody = h("div", { class: "t-map" }, map.el, map.controls);
  mount(el, h("div", { class: "t-dash" },
    warn,
    h("div", { class: "t-col" },
      box("KENNZAHLEN", kpis, { right: "letzte " + rangeText(r) }),
      box("VERLAUF NACH STUFE", chartEl, { right: chartRight }),
      box("DIENSTE", svcEl, { right: "Anteil Verbindungen", cls: "grow" })),
    h("div", { class: "t-col" },
      box("HERKUNFT · KARTE", mapBody, { right: "Rad: Zoom" }),
      box("TOP-ANGREIFER", topEl, { right: "Verbindungen" }),
      box("HERKUNFT NACH LAND", landEl, { cls: "grow" })),
    h("div", { class: "t-col" },
      box("LIVE-LOG", logEl, { right: pauseBtn, cls: "grow on t-logbox" }),
      box("FUNDE", funEl, { right: "Nachlade-Adressen" }))));
  measure(el);
  fill();
  fillExtra();
  const ro = new ResizeObserver(() => { measure(el); layout(); });
  ro.observe(chartEl);
  ctx.onCleanup(() => ro.disconnect());
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => { if (ctx.current()) { measure(el); layout(); } });

  // Log mit den letzten Ereignissen vorbelegen (die API liefert die neuesten zuerst), danach live
  api("events?limit=120").then((rows) => {
    if (!ctx.current()) return;
    buf.unshift(...(rows || []).slice().reverse());
    fillLog();
  }).catch(() => fillLog());

  // Gerade aktiv: Stufen für Log, Top-Liste, Bögen und Lage
  let actList = [];
  d.actP.then((act) => {
    if (!act || !ctx.current()) return;
    actList = act.attacks || [];
    for (const a of actList) if (!a.own) stufeOf.set(a.ip, Math.max(stufeOf.get(a.ip) ?? 0, a.stufe));
    map.seedActive(actList.filter((a) => !a.own));
    setLage(actList);
    fillTop();
    if (!paused) fillLog();
  });
  ctx.live((e) => {
    map.track(e);
    addLog(e);
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
  // Daten im Hintergrund auffrischen, ohne Karte und Log neu aufzubauen
  ctx.every(60000, async () => {
    if (document.hidden) return;
    try {
      const nd = await loadDashboard(r);
      if (!ctx.current() || state.range !== r) return;
      d = nd;
      fill();
      fillExtra();
      nd.actP.then((act) => { if (act && ctx.current()) { actList = act.attacks; setLage(actList); } });
    } catch { /* nächster Versuch */ }
  });
  ctx.every(30000, () => setLage(actList)); // Lage altert auch ohne neue Meldungen
}

// Link auf die Seite Angriffe mit genau diesem Filter (aus der Übersicht, also ohne alte Filter)
function attHrefFresh(token) {
  return "#/attacks?" + new URLSearchParams({ q: token });
}
