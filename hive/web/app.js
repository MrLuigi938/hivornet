// Hivornet Web-UI: Anmeldung, Navigation und alle Ansichten.
import {
  h, mount, api, AuthError, fmtNum, fmtBytes, fmtDur, fmtTime, fmtDateTime, relTime, toMs, store, flag, hideTip, panels, plural, credText, activeBadge, ACTIVE_MS, ACTIVE_TITLE,
} from "./dom.js";
import { worldMap, timeline, toplist, sparkline, svcName, svcColor, countryName } from "./charts.js";
// Angriffe gebündelt (Seite "Angriffe", "Gerade aktiv" im Dashboard)
import { viewAttacks, viewSwitch, attackCard, attackRow, liveAttacks, noteBrute, bruteStatsParam, bruteStatsNote, historyView, HISTORY_FROM, BRUTE_TITLE, sharedFromQuery, sharedQS, sharedParams, sharedRange, sharedBar, STUFE } from "./attacks.js";
// Analyse, Bericht, Mitschnitt, Abgleich und Zusatz-Einstellungen
import { viewAnalysis, viewCreds, viewTarpit, viewInsights, exposureCard } from "./auswertung.js";
import { reportCard, chainCard, ttyCard, intelCard, homeLocation } from "./extra.js";
// Einstellungen mit Unterseiten (#/settings/<bereich>)
import { viewSettings } from "./settings.js";
import { applyTheme, activeSkin, skinReady, onSkinChange } from "./themes.js";
import { viewFunde } from "./funde.js";
// Hardware-Monitor im Reiter System
import { hardwareCard } from "./hardware.js";

const app = document.getElementById("app");
const state = { user: null, range: store("range") || "24h", es: null, liveFns: new Set(), cleanup: null, leaveGuard: null };

// Navigation in der Kopfleiste; Einstellungen, System und Protokolle stehen im Benutzermenü.
const NAV = [
  ["#/", "Dashboard"], ["#/attacks", "Angriffe"], ["#/analysis", "Analyse"], ["#/insights", "Erkenntnisse"], ["#/funde", "Funde"],
  ["#/creds", "Zugangsdaten"], ["#/tarpit", "Tarpit"], ["#/system", "System"],
];
const RANGES = [["24h", "24 Std"], ["7d", "7 Tage"], ["30d", "30 Tage"]];
const TYPE_NAME = {
  connect: "Verbindung", disconnect: "Ende", login: "Login", request: "Anfrage", command: "Befehl",
  download: "Download", client_version: "Client", payload: "Daten", tls: "TLS", fingerprint: "Fingerabdruck",
  tty: "Mitschnitt", ai_reply: "KI-Antwort", condensed: "Verdichtet",
};
// Muss alle Dienste des Honeypots enthalten (Test TestServiceListsInSync im Honeypot).
const SERVICES = ["ssh", "telnet", "http", "https", "ftp", "smtp", "redis", "mysql", "dockerapi", "rdp", "vnc", "sip", "snmp", "dns", "ssh-tarpit", "raw",
  "adb", "mqtt", "postgres", "elasticsearch", "ollama", "kubernetes"];
const MODE_NAME = { emulate: "Aufzeichnen", tarpit: "Tarpit", hybrid: "Hybrid" };

// ---------- Theme ----------
// Farbmodus und Theme: themes.js (Einstellungen → Darstellung). Ein Theme kann den Rahmen
// (shell), die Übersicht (dashboard) und Seitenwechsel (onRoute) übernehmen; Ablauf und
// Regeln stehen im Kopf von themes.js und in docs/ARCHITEKTUR.md.
applyTheme();
// Wechsel ohne Neuladen: alte Ansicht und altes Theme abräumen, Rahmen neu, Seite neu.
onSkinChange((next, prev) => {
  if (!state.user || !mainEl) return;
  if (state.cleanup) { state.cleanup(); state.cleanup = null; }
  try { prev.mod?.cleanup?.(); } catch (e) { console.error(e); }
  renderShell();
  route();
});
// Hook eines Themes aufrufen; Fehler landen in der Konsole, dann gilt der Standard (undefined).
function skinHook(name, ...args) {
  const fn = activeSkin().mod?.[name];
  if (typeof fn !== "function") return undefined;
  try { return fn(...args); } catch (e) { console.error(`Theme-Einhängepunkt ${name}:`, e); return undefined; }
}

// ---------- Start, Anmeldung ----------

async function boot() {
  try { state.user = await api("me", { noAuthRedirect: true }); } catch { state.user = null; }
  if (!state.user) {
    // Frische Installation ohne Admin-Konto: Assistent statt Anmeldung
    const st = await api("setup", { noAuthRedirect: true }).catch(() => null);
    if (st && st.needed) return showSetup(st);
    return showLogin();
  }
  await skinReady(); // Rahmen erst bauen, wenn CSS und Modul des Themes da sind
  renderShell();
  startStream();
  startLivePoll();
  route();
}

function showLogin(msg) {
  stopStream();
  state.user = null;
  const err = h("div", { class: "msg err", hidden: !msg }, msg || "");
  const user = h("input", { name: "username", autocomplete: "username", required: true, value: "admin" });
  const pass = h("input", { name: "password", type: "password", autocomplete: "current-password", required: true });
  const form = h("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      err.hidden = true;
      try {
        await api("login", { method: "POST", body: { username: user.value, password: pass.value }, noAuthRedirect: true });
        boot();
      } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    },
  },
  h("div", { class: "brand" }, h("img", { src: "favicon.svg", alt: "" }), "Hivornet"),
  err, h("label", null, "Benutzername", user), h("label", null, "Passwort", pass),
  h("button", { class: "btn primary", type: "submit" }, "Anmelden"));
  mount(app, h("div", { class: "login" }, form, credit(false)));
  pass.focus();
}

// Fußzeile wie in den anderen Projekten: Name, Version, Urheber. In der Anwendung
// zeigt sie außerdem, wenn eine neuere Version veröffentlicht wurde.
function credit(inApp) {
  const u = state.user || {};
  const ver = inApp && u.version && u.version !== "dev" ? h("span", { class: "version" }, u.version) : null;
  const msg = h("span", { class: "muted" });
  let update = null;
  if (inApp && u.update) {
    const link = h("a", { class: "update", href: u.update.url, target: "_blank", rel: "noopener noreferrer", title: "Was ist neu?" }, `⬆ Version ${u.update.version} ist da`);
    const btn = u.can_install && u.role === "admin" ? h("button", {
      class: "btn small",
      onclick: async () => {
        if (!confirm(`Hivornet jetzt auf Version ${u.update.version} aktualisieren? Die Dienste starten dabei neu.`)) return;
        btn.disabled = true;
        try {
          await api("update", { method: "POST" });
          msg.textContent = "Update läuft. Die Seite lädt in etwa zwei Minuten neu.";
          setTimeout(() => location.reload(), 120000);
        } catch (e) { msg.textContent = e.message; btn.disabled = false; }
      },
    }, "Jetzt aktualisieren") : null;
    update = [link, btn, msg];
  }
  return h("footer", { class: "credit" },
    h("span", null, inApp ? [h("b", null, "Hivornet"), ver, " · "] : null,
      "Erdacht mit ", h("span", { class: "heart", "aria-label": "Liebe" }, "♥"), " von ",
      h("a", { href: "https://github.com/MrLuigi938", target: "_blank", rel: "noopener noreferrer" }, "Luis Blum"),
      " · gebaut mit KI ✨"),
    update);
}

// Ersteinrichtung: Passwort und Standort festlegen, danach ist man angemeldet.
function showSetup(st) {
  stopStream();
  const err = h("div", { class: "msg err", hidden: true });
  const p1 = h("input", { type: "password", autocomplete: "new-password", required: true, minlength: 10, maxlength: 72 });
  const p2 = h("input", { type: "password", autocomplete: "new-password", required: true, minlength: 10, maxlength: 72 });
  const home = st.home || { lat: 51.1, lon: 10.4, label: "Honeypot" };
  const lat = h("input", { type: "number", step: 0.1, min: -90, max: 90, value: home.lat });
  const lon = h("input", { type: "number", step: 0.1, min: -180, max: 180, value: home.lon });
  const label = h("input", { maxlength: 40, value: home.label || "" });
  const btn = h("button", { class: "btn primary", type: "submit" }, "Einrichten und starten");
  const form = h("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      err.hidden = true;
      if (p1.value !== p2.value) { err.textContent = "Die beiden Passwörter stimmen nicht überein."; err.hidden = false; return; }
      btn.disabled = true;
      try {
        await api("setup", {
          method: "POST", noAuthRedirect: true,
          body: { password: p1.value, home: { lat: Number(lat.value), lon: Number(lon.value), label: label.value.trim() } },
        });
        boot();
      } catch (ex) { err.textContent = ex.message; err.hidden = false; btn.disabled = false; }
    },
  },
  h("div", { class: "brand" }, h("img", { src: "favicon.svg", alt: "" }), "Hivornet einrichten"),
  h("p", { class: "sub" }, "Willkommen. Lege ein Passwort für die Verwaltung fest; der Benutzername ist „admin“. Alles Weitere stellst du danach in Ruhe unter Einstellungen ein."),
  err,
  h("label", null, "Passwort (10 bis 72 Zeichen)", p1),
  h("label", null, "Passwort wiederholen", p2),
  h("h3", null, "Standort für die Karte (ungefähr genügt)"),
  h("div", { class: "pair" }, h("label", null, "Breite", lat), h("label", null, "Länge", lon)),
  h("label", null, "Bezeichnung", label),
  h("p", { class: "muted" }, "Dorthin zeigen die Angriffslinien auf der Karte. Beispiel Berlin: Breite 52.5, Länge 13.4. Der Ort wird nirgends veröffentlicht."),
  btn);
  mount(app, h("div", { class: "login setup" }, form, credit(false)));
  p1.focus();
}

async function logout() {
  try { await api("logout", { method: "POST" }); } catch { /* egal */ }
  showLogin();
}

// ---------- Live-Stream ----------

function startStream() {
  stopStream();
  const es = new EventSource("api/stream");
  state.es = es;
  es.onopen = () => setLive(true);
  es.onerror = () => {
    setLive(false);
    if (es.readyState !== EventSource.CLOSED || state.es !== es) return; // Browser verbindet selbst neu
    // Der Server hat abgelehnt (z. B. Sitzung abgelaufen): prüfen und reagieren.
    api("me", { noAuthRedirect: true })
      .then(() => setTimeout(() => { if (state.es === es) startStream(); }, 5000))
      .catch((e) => {
        if (state.es !== es) return;
        if (e.message === "nicht angemeldet") showLogin("Sitzung abgelaufen, bitte erneut anmelden.");
        else setTimeout(() => { if (state.es === es) startStream(); }, 10000); // Hive nicht erreichbar
      });
  };
  es.onmessage = (m) => {
    let ev;
    try { ev = JSON.parse(m.data); } catch { return; }
    for (const fn of state.liveFns) { try { fn(ev); } catch (e) { console.error(e); } }
  };
}
function stopStream() { if (state.es) state.es.close(); state.es = null; clearInterval(liveTimer); }
function setLive(on) {
  const d = document.getElementById("live");
  if (!d) return;
  d.classList.toggle("on", on);
  d.dataset.state = on ? "live" : "getrennt";
  renderLiveText();
}
// Live-Anzeige in der Kopfleiste, auf jeder Seite: aktive Angreifer (letzte 15 Minuten)
// und gerade festgehaltene Verbindungen, beides anklickbar. Alle 15 s vom Hive geholt.
let liveStat = null, liveTimer = null;
async function pollLive() {
  try { liveStat = await api("stats/live", { noAuthRedirect: true }); } catch { /* nächster Versuch */ }
  renderLiveText();
  for (const fn of liveStatFns) fn(liveStat);
}
// Zahl der aktiven Angreifer vom Hive (null: noch nicht geholt); dieselbe Zahl wie in der Kopfzeile
export const liveStatFns = new Set();
export const liveActiveCount = () => (liveStat ? liveStat.active : null);
function startLivePoll() {
  clearInterval(liveTimer);
  pollLive();
  liveTimer = setInterval(() => { if (!document.hidden) pollLive(); }, 15000);
}
function renderLiveText() {
  const d = document.getElementById("live");
  if (!d) return;
  const st = d.dataset.state || "verbinde …";
  if (st !== "live") { mount(d.lastChild, st); return; }
  mount(d.lastChild, "LIVE", liveStat ? [
    " · ", h("a", { href: "#/attacks", title: ACTIVE_TITLE.replace("aktiv", "Aktive Angreifer") }, `${fmtNum(liveStat.active)} aktiv`),
    liveStat.tarpits ? [" · ", h("a", { href: "#/tarpit", title: "Gerade im Tarpit festgehalten: wer, seit wann" }, `${fmtNum(liveStat.tarpits)} im Tarpit`)] : null,
  ] : null);
}
function onLive(fn) { state.liveFns.add(fn); return () => state.liveFns.delete(fn); }

// ---------- Rahmen und Router ----------

let mainEl, topEl;

function renderShell() {
  const isAdmin = state.user.role !== "viewer";
  const menu = h("div", { class: "menu", hidden: true },
    h("div", { class: "info" }, "Angemeldet als ", h("b", null, state.user.username), state.user.role === "viewer" ? " (nur ansehen)" : ""),
    isAdmin ? h("a", { href: "#/settings" }, "Einstellungen") : null,
    h("a", { href: "#/settings/darstellung" }, "Darstellung"),
    state.user.logs ? h("a", { href: "#/logs" }, "Protokolle") : null,
    h("hr"),
    h("button", { class: "item", onclick: logout }, "Abmelden"),
    h("div", { class: "info" }, "Version ", state.user.version));
  const userBtn = h("button", { "aria-haspopup": "true", "aria-expanded": "false", onclick: (e) => {
    e.stopPropagation();
    menu.hidden = !menu.hidden;
    userBtn.setAttribute("aria-expanded", String(!menu.hidden));
  } }, h("span", { class: "avatar" }, (state.user.username || "?").slice(0, 1).toUpperCase()), state.user.username);
  // nur ein Klick-Abräumer, auch wenn der Rahmen neu gebaut wird (Anmeldung, Theme-Wechsel)
  if (closeMenu) document.removeEventListener("click", closeMenu);
  closeMenu = (e) => { if (!menu.hidden && !menu.contains(e.target)) { menu.hidden = true; userBtn.setAttribute("aria-expanded", "false"); } };
  document.addEventListener("click", closeMenu);
  menu.addEventListener("click", (e) => { if (e.target.closest("a")) menu.hidden = true; });
  // Bausteine, die ein Theme in seinem eigenen Rahmen anordnen kann (themes.js: shell)
  const teile = {
    user: state.user, nav: NAV, logout,
    brand: h("a", { class: "brand", href: "#/" }, h("img", { src: "favicon.svg", alt: "" }), "Hivornet"),
    live: h("span", { id: "live", class: "livepill", role: "status" }, h("i"), h("span", null, "verbinde …")),
    userMenu: h("div", { class: "usermenu" }, userBtn, menu),
    credit: credit(true),
  };
  const sk = skinHook("shell", app, teile);
  if (sk && sk.main && sk.top) {
    mainEl = sk.main;
    topEl = sk.top;
  } else {
    mainEl = h("div");
    topEl = h("div", { class: "top" });
    mount(app,
      h("header", { class: "topbar" },
        teile.brand,
        h("nav", { class: "nav" }, NAV.map(([href, label]) => h("a", { href, "data-navlink": "" }, label))),
        h("div", { class: "grow" }),
        teile.live,
        teile.userMenu),
      h("main", { class: "main" }, topEl, mainEl, teile.credit));
  }
  if (state.es && state.es.readyState === EventSource.OPEN) setLive(true);
  window.onhashchange = route;
}
let closeMenu = null;

// ---------- Zeitraum ----------
// Feste Auswahl plus „Eigener“: Zahl und Einheit, z. B. 3 Monate (Server: rangeDur in api.go).
const RANGE_UNITS = [["d", "Tage", "Tag", 1095], ["w", "Wochen", "Woche", 156], ["m", "Monate", "Monat", 36]];
const RANGE_RE = /^([1-9]\d{0,3})([hdwm])$/;
const rangeOK = (v) => v === "all" || RANGE_RE.test(v || "");
const rangeDays = (v) => { const m = RANGE_RE.exec(v || ""); return m ? Number(m[1]) * { h: 1 / 24, d: 1, w: 7, m: 30 }[m[2]] : 0; };
function rangeLabel(v) {
  const m = RANGE_RE.exec(v || "");
  if (!m) return v;
  const n = Number(m[1]);
  if (m[2] === "h") return n + " Std";
  const u = RANGE_UNITS.find(([k]) => k === m[2]);
  return `${n} ${n === 1 ? u[2] : u[1]}`;
}
function rangePicker(cur, presets, pick) {
  const box = h("div", { class: "range-pick" });
  const render = () => {
    const custom = !presets.some(([v]) => v === cur);
    const m = custom ? /^(\d+)([dwm])$/.exec(cur) : null;
    const num = h("input", { type: "number", min: 1, max: 1095, value: m ? m[1] : 3, "aria-label": "Anzahl", style: { width: "70px" } });
    const unit = h("select", { "aria-label": "Einheit" }, RANGE_UNITS.map(([u, l]) => h("option", { value: u, selected: (m ? m[2] : "m") === u }, l)));
    const ret = state.user && state.user.retention_days;
    const pop = h("form", { class: "range-pop", hidden: true, onsubmit: (e) => {
      e.preventDefault();
      const n = Math.floor(Number(num.value)), max = RANGE_UNITS.find(([u]) => u === unit.value)[3];
      if (!(n >= 1)) { num.focus(); return; }
      set(`${Math.min(n, max)}${unit.value}`);
    } },
      h("div", { class: "range-row" }, h("span", null, "Letzte"), num, unit, h("button", { class: "btn small", type: "submit" }, "Anwenden")),
      ret ? h("div", { class: "muted aw-small" }, `Angriffe, Listen und Muster reichen ${ret} Tage zurück (Einstellungen → Rohdaten aufbewahren); der Verlauf der Verbindungen bis 400 Tage.`) : null);
    const btn = h("button", { class: custom ? "on" : "", "aria-expanded": "false", title: "Eigenen Zeitraum wählen",
      onclick: () => { pop.hidden = !pop.hidden; btn.setAttribute("aria-expanded", String(!pop.hidden)); if (!pop.hidden) num.focus(); } },
      custom ? rangeLabel(cur) + " ▾" : "Eigener …");
    pop.addEventListener("keydown", (e) => { if (e.key === "Escape") { pop.hidden = true; btn.focus(); } });
    const short = ret && rangeDays(cur) > ret;
    mount(box,
      h("div", { class: "seg", role: "group", "aria-label": "Zeitraum" },
        presets.map(([v, l]) => h("button", { class: cur === v ? "on" : "", "aria-pressed": String(cur === v), onclick: () => set(v) }, l)), btn),
      pop,
      short ? h("span", { class: "range-warn", title: `Rohdaten werden ${ret} Tage aufbewahrt; Angriffe und Listen zeigen nur diese Zeit.` }, `nur ${ret} Tage Daten`) : null);
  };
  const set = (v) => { cur = v; render(); pick(v); };
  render();
  return box;
}

let topTarget = null; // bei stiller Aktualisierung baut header() unsichtbar vor
function header(title, { range = false, extra = null } = {}) {
  if (range && !RANGE_RE.test(state.range)) state.range = "24h";
  const seg = range ? rangePicker(state.range, RANGES, (v) => { state.range = v; store("range", v); route(); }) : null;
  mount(topTarget || topEl, h("h1", null, title), h("div", { class: "grow" }), extra, seg);
}

const routes = [
  [/^#?\/?$/, viewDashboard], [/^#\/attacks(\?.*)?$/, viewAttacks], [/^#\/feed(\?.*)?$/, viewFeed], [/^#\/sessions(\?.*)?$/, viewSessions],
  [/^#\/session\/(.+)$/, viewSession], [/^#\/attacker\/(.+)$/, viewAttacker], [/^#\/creds$/, viewCreds],
  [/^#\/tarpit$/, viewTarpit], [/^#\/settings(?:\/([a-z]+))?$/, viewSettings], [/^#\/system$/, viewSystem],
  [/^#\/analysis$/, viewAnalysis], [/^#\/insights$/, viewInsights], [/^#\/funde(?:\?(.*))?$/, viewFunde], [/^#\/logs(\?.*)?$/, viewLogs],
];

// route({ quiet: true }) aktualisiert die aktuelle Seite unauffällig: Die neue Fassung wird
// unsichtbar aufgebaut und erst dann ausgetauscht, an derselben Scrollstelle, ohne "Lade …".
// Das nutzen die regelmäßigen Aktualisierungen (Dashboard, Tarpit, System).
async function route(opts = {}) {
  if (!mainEl) return;
  // Ungespeicherte Änderungen (Einstellungen): beim Wechsel nachfragen, sonst zurück zur alten Adresse
  const want = location.hash || "#/";
  if (state.leaveGuard && shownHash !== null && want !== shownHash && !state.leaveGuard()) {
    history.replaceState(null, "", shownHash);
    return;
  }
  shownHash = want;
  const quiet = opts.quiet === true && mainEl.firstChild;
  if (state.cleanup) { state.cleanup(); state.cleanup = null; }
  hideTip(); // Tooltip der vorigen Ansicht nicht stehen lassen
  const hash = location.hash || "#/";
  // Einzelansicht, Angreifer und Sitzungen gehören in der Navigation zu "Angriffe"
  const navHash = /^#\/(feed|attacker\/|session)/.test(hash) ? "#/attacks" : hash;
  for (const a of document.querySelectorAll("a[data-navlink]")) {
    const href = a.getAttribute("href");
    const on = href === "#/" ? navHash === "#/" || navHash === "" : navHash.startsWith(href);
    a.classList.toggle("on", on);
    if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  }
  if (!quiet) skinHook("onRoute", { hash, navHash });
  const [, view, m] = routes.map(([re, v]) => [re, v, hash.match(re)]).find(([, , m]) => m) || [null, viewDashboard, []];
  // Jede Ansicht zeichnet in ihren eigenen Behälter. Wird inzwischen weiternavigiert,
  // landet eine verspätete Ansicht in einem Behälter, der nicht mehr angezeigt wird,
  // und ihre Live-Handler und Timer werden sofort wieder abgeräumt.
  const seq = ++routeSeq;
  const host = h("div", null, quiet ? null : h("p", { class: "muted" }, "Lade …"));
  if (quiet) topTarget = h("div");
  else { topTarget = null; mount(mainEl, host); }
  const cleanups = [];
  const cleanupAll = () => cleanups.splice(0).forEach((f) => f());
  state.cleanup = cleanupAll;
  try {
    const ctx = {
      live: (fn) => cleanups.push(onLive(fn)),
      every: (ms, fn) => { const t = setInterval(fn, ms); cleanups.push(() => clearInterval(t)); },
      onCleanup: (fn) => cleanups.push(fn),
      current: () => seq === routeSeq,
    };
    await view(host, ctx, ...(m || []).slice(1).map((x) => (x == null ? "" : decodeURIComponent(x))));
    if (seq !== routeSeq) cleanupAll();
    else if (quiet) {
      // erst jetzt austauschen; Scrollstelle und Höhe halten, damit nichts springt
      const y = window.scrollY;
      mainEl.style.minHeight = mainEl.offsetHeight + "px";
      mount(topEl, [...topTarget.childNodes]);
      topTarget = null;
      mount(mainEl, host);
      window.scrollTo(0, y);
      requestAnimationFrame(() => { mainEl.style.minHeight = ""; window.scrollTo(0, y); });
    }
  } catch (e) {
    cleanupAll();
    if (seq !== routeSeq) return;
    if (quiet) { topTarget = null; return; } // stille Aktualisierung fehlgeschlagen: alte Fassung stehen lassen
    if (e instanceof AuthError) return showLogin("Bitte erneut anmelden.");
    mount(host, h("div", { class: "msg err" }, "Fehler: " + e.message));
  }
}
let routeSeq = 0;
let shownHash = null; // zuletzt angezeigte Adresse (für state.leaveGuard)

// ---------- gemeinsame Bausteine ----------

const card = (title, ...kids) => h("section", { class: "card" }, title ? h("div", { class: "head" }, h("h2", null, title)) : null, ...kids);
const tile = (label, value, hint) => h("div", { class: "card tile" }, h("div", { class: "label" }, label), h("div", { class: "value num" }, value), hint ? h("div", { class: "hint" }, hint) : null);
const cc = (code, name) => (code ? h("span", { class: "badge cc", title: name || countryName(code) }, flag(code), flag(code) ? " " : null, code) : null);
const ipLink = (ip) => h("a", { href: "#/attacker/" + encodeURIComponent(ip) }, ip);
const svcBadge = (svc, port) => h("span", { class: "badge" }, h("i", { class: "swatch", style: { background: svcColor(svc) } }), svcName(svc), port ? ":" + port : "");

function parseData(e) {
  if (!e.data) return {};
  if (typeof e.data === "string") { try { return JSON.parse(e.data); } catch { return {}; } }
  return e.data;
}

// Kurzbeschreibung eines Ereignisses (immer als Text, nie als HTML)
function describe(e) {
  const d = parseData(e);
  switch (e.type) {
    case "login": {
      const ok = d.success ? h("span", { class: "badge ok" }, "erfolgreich") : null;
      if (d.cookie) return `${e.username || "–"} (nur Benutzername, aus dem RDP-Cookie)`;
      const pw = d.password_hashed ? "(Passwort gehasht)" : e.password;
      return [`${e.username || "(leer)"} / ${pw || "(leer)"}`, ok ? " " : null, ok];
    }
    case "command": return d.input || "";
    case "request": return d.forward_to ? `Weiterleitung nach ${d.forward_to}` : `${d.method || ""} ${d.path || ""}`;
    case "download": return `${d.upload ? "Upload " + (d.filename || "") : d.url || ""}${d.failed ? " (fehlgeschlagen)" : ""}`;
    case "client_version": return d.version || "";
    case "payload": return d.text || "";
    case "tls": return d.sni ? `SNI ${d.sni}` : "TLS";
    case "fingerprint": return d.hassh ? `HASSH ${d.hassh}` : "";
    case "tty": return `Terminal-Mitschnitt, ${fmtBytes(d.size)} (in der Sitzung ansehen)`;
    case "ai_reply": return [h("span", { class: "badge ai" }, "KI"), " ", h("span", { class: "mono" }, d.input || ""), " → ",
      h("span", { class: "mono muted", title: d.output || "" }, String(d.output || "").replace(/\s+/g, " ").slice(0, 160) || "(leer)")];
    case "connect": return d.mode ? `Modus ${MODE_NAME[d.mode] || d.mode}` : "";
    case "disconnect": return [`Dauer ${fmtDur(e.duration_ms)}`, e.tarpit ? [" ", h("span", { class: "badge tarpit" }, `festgehalten ${fmtDur(e.tarpit_ms)}`)] : null];
  }
  return "";
}

// group: gleichartige Ereignisse derselben IP direkt hintereinander, als eine Zeile mit Zähler
function eventRow(e, { fresh = false, showIP = true, group = null } = {}) {
  const items = group || [e];
  const summaryDet = () => (items.length > 1 ? [describe(e), h("span", { class: "muted" }, `  · und ${fmtNum(items.length - 1)} weitere`)] : describe(e));
  const det = h("td", { class: "det" }, summaryDet());
  const tr = h("tr", { class: "click" + (fresh ? " new" : ""), title: "Klicken oder Eingabetaste für Details", tabindex: 0 },
    h("td", { class: "num" }, fmtTime(e.ts)),
    h("td", null, svcBadge(e.service, e.dst_port)),
    h("td", null, TYPE_NAME[e.type] || e.type, items.length > 1 ? h("span", { class: "xn" }, "×" + fmtNum(items.length)) : null),
    showIP ? h("td", null, ipLink(e.src_ip), " ", cc(e.country, e.country_name)) : null,
    det);
  let open = false;
  tr.addEventListener("keydown", (ev) => {
    if ((ev.key === "Enter" || ev.key === " ") && ev.target === tr) { ev.preventDefault(); tr.click(); }
  });
  tr.addEventListener("click", (ev) => {
    if (ev.target.closest("a")) return;
    open = !open;
    tr.classList.toggle("expanded", open);
    if (items.length > 1) {
      mount(det, summaryDet(), open ? h("div", { style: { marginTop: "6px" } }, items.map((x) => h("div", null, h("span", { class: "muted num" }, fmtTime(x.ts), "  "), describe(x)))) : null);
      return;
    }
    mount(det, describe(e), open ? h("pre", { class: "json" }, JSON.stringify({
      zeit: fmtDateTime(e.ts), sensor: e.sensor, sitzung: e.session, quelle: `${e.src_ip}:${e.src_port}`,
      ort: [e.city, e.country_name].filter(Boolean).join(", ") || undefined, netz: e.asn ? `AS${e.asn} ${e.as_org}` : undefined,
      daten: parseData(e),
    }, null, 2)) : null);
  });
  return tr;
}

const evTable = (rows, opts) => h("div", { class: "tablewrap" }, h("table", null,
  h("thead", null, h("tr", null, h("th", null, "Zeit"), h("th", null, "Dienst"), h("th", null, "Typ"), opts?.showIP === false ? null : h("th", null, "Quelle"), h("th", null, "Details"))),
  h("tbody", null, rows.map((e) => eventRow(e, opts)))));

const isNoise = (e) => e.type === "connect" || e.type === "disconnect";

// Warnungen des Hive (Netzsperre fehlt, Sensor still, Speicher knapp …)
function warningsBox(list, link) {
  if (!list || !list.length) return null;
  return h("div", { class: "warnings" }, list.map((w) => h("div", { class: "msg " + (w.level === "critical" ? "err" : "warn") },
    w.level === "critical" ? "Achtung: " : "Hinweis: ", w.text)),
  link ? h("a", { href: "#/system" }, "Details unter System") : null);
}

// ---------- Dashboard ----------

// Letzter Stand von "Gerade aktiv" über Aktualisierungen hinweg (null: noch nie geladen)
let dashActive = null;

// Daten der Übersicht für einen Zeitraum, gemeinsam für den Standard und Themes (dashboard-Hook).
// actP: "Gerade aktiv" ist die teuerste Abfrage; niemand wartet darauf, die Liste folgt.
async function loadDashboard(r = state.range) {
  const q = (p) => api(p + (p.includes("?") ? "&" : "?") + "range=" + r);
  const nb = bruteStatsParam(); // Zugangsdaten, Netzbetreiber, Befehle ohne Dauer-Brute-Force
  const actP = api("attacks?active=1&limit=60").catch(() => null);
  const [ser, tl, mp, countries, ports, ips, asns, creds, cmds, sys] = await Promise.all([
    q("stats/series"), q("stats/timeline"), q("stats/map"),
    q("stats/top?field=country&limit=100"), q("stats/top?field=port"), q("stats/top?field=ip"), q("stats/top?field=asn" + nb),
    q("stats/top?field=cred" + nb), q("stats/top?field=command" + nb),
    api("system").catch(() => null),
  ]);
  const home = await homeLocation();
  return { range: r, ser, tl, mp, countries, ports, ips, asns, creds, cmds, sys, home, actP };
}

async function viewDashboard(el, ctx) {
  header("Dashboard", { range: true });
  const r = state.range;
  const data = await loadDashboard(r);
  if (activeSkin().mod?.dashboard) {
    try { return await activeSkin().mod.dashboard(el, ctx, data); } catch (e) { console.error("Theme-Übersicht:", e); }
  }
  const { ser, tl, mp, countries, ports, ips, asns, creds, cmds, sys, home, actP } = data;

  // ---- Kennzahlen mit Verlauf und Vergleich zum Zeitraum davor ----
  const tiles = {};
  // Jede Kennzahl führt zur passenden Liste (Zeitraum wie im Dashboard)
  const KPIS = [
    ["connect", "Verbindungen", false, `#/attacks?range=${r}`],
    ["ips", "Angreifer-IPs", false, `#/attacks?range=${r}`],
    ["login", "Login-Versuche", false, `#/feed?type=login`,
      ser.totals.login_brute ? `Davon ${fmtNum(ser.totals.login_brute)} verdichtete Versuche erkannter Dauer-Brute-Forcer.` : ""],
    ["request", "Web-Anfragen", false, `#/feed?type=request`],
    ["success", "Logins angenommen", true, `#/attacks?range=${r}&success=1`],
    ["fetch", "Nachladeversuche", true, `#/attacks?range=${r}&q=nachladen:ja`,
      "Befehle mit Download-Adresse (wget, curl, tftp …) über alle Dienste. Heruntergeladen wird dabei nichts; echte Downloads gibt es nur über Cowrie mit Internetfreigabe (Stufe „Datei nachgeladen“)."],
  ];
  const kpi = ([key, label, alarm, href, help]) => {
    const v = Number(ser.totals[key] || 0), p = Number(ser.prev[key] || 0);
    // Prozentvergleich nur mit tragfähiger Basis: Der Zeitraum davor muss zu mindestens der Hälfte nach dem
    // Beginn der Aufzeichnung liegen und genug Ereignisse haben. Sonst "neu" bzw. gar kein Vergleich.
    const span = Date.now() - ser.from, early = ser.data_from > 0 && ser.data_from > ser.from - span / 2;
    const base = !early && p >= 20;
    const delta = base ? Math.round(((v - p) / p) * 100) : null;
    const value = h("span", null, fmtNum(v));
    const isNew = !base && early && v > 0;
    const t = h("a", { class: "card tile link" + (alarm && v ? " alarm" : ""), href, title: (help ? help + " " : "") + (p ? `Zeitraum davor: ${fmtNum(p)}. ` : "") + (isNew ? "Der Zeitraum davor liegt zum großen Teil vor dem Beginn der Aufzeichnung, ein Prozentvergleich wäre nicht aussagekräftig. " : "") + "Klick zeigt die Liste dazu." },
      h("div", { class: "label" }, label),
      h("div", { class: "value num" }, value, delta !== null && delta !== 0 ? h("small", { class: delta > 0 ? "up" : "down" }, `${delta > 0 ? "▲" : "▼"} ${Math.abs(delta)} %`) : isNew ? h("small", null, "neu") : null),
      sparkline(ser.series[key] || []));
    tiles[key] = { value, n: v };
    return t;
  };

  // ---- Karte ----
  // Angriffslinien als Spur: Einstellungen → Darstellung (Standard aus)
  const map = worldMap(mp, { home, countries, arcs: store("mapSpur") === "1" ? "spur" : "aktiv" });

  // ---- Gerade aktiv (Angriffe der letzten 15 Minuten) ----
  // Beim stillen Aktualisieren (alle 2 Minuten) den bisherigen Stand übernehmen, statt die Liste
  // leer mit "Lade …" neu zu beginnen, bis die Abfrage zurück ist.
  const active = new Map(dashActive || []);
  let actLoaded = dashActive !== null;
  dashActive = active;
  const openRows = new Set();
  const actList = h("div", { class: "list alist" });
  const actCount = h("span", { class: "hint" });
  const rowEls = new Map();
  const setActInfo = () => {
    actCount.textContent = active.size ? `${active.size} Angreifer, nach IP gebündelt` : "";
  };
  const renderActive = () => {
    const now = Date.now();
    for (const [id, a] of active) if (now - a.last > ACTIVE_MS) active.delete(id);
    const list = [...active.values()].sort((x, y) => y.last - x.last);
    rowEls.clear();
    setActInfo();
    const keep = actList.scrollTop;
    requestAnimationFrame(() => { actList.scrollTop = keep; });
    mount(actList, list.length ? list.map((a) => { const r = attackRow(a, { open: openRows }); rowEls.set(a.id, r); return r; })
      : h("div", { class: "empty" }, actLoaded ? "Gerade ist niemand aktiv. Neue Angriffe erscheinen hier sofort." : "Lade …"));
  };
  // Live: nur die geänderte Zeile ersetzen und nach oben setzen
  const upsertActive = (a) => {
    active.set(a.id, a);
    const old = rowEls.get(a.id), r = attackRow(a, { fresh: true, open: openRows });
    rowEls.set(a.id, r);
    if (old) old.remove();
    actList.querySelector(".empty")?.remove();
    actList.prepend(r);
    setActInfo();
  };

  mount(el, h("div", { class: "lage" },
    warningsBox(sys && sys.warnings, true),
    h("div", { class: "grid kpi6 kpis" }, KPIS.map(kpi)),
    h("section", { class: "card mapcard" }, h("div", { class: "head" }, h("h2", null, "Herkunft der Angriffe"), h("div", { class: "grow" }), map.controls), map.el,
      h("div", { class: "legend", style: { marginTop: "8px", marginBottom: 0 } },
        h("span", null, h("i", { class: "swatch", style: { background: "var(--heat)" } }), "Land: Verbindungen im Zeitraum"),
        h("span", null, h("i", { class: "swatch", style: { background: "var(--dot)", borderRadius: "50%" } }), "Ort"),
        h("span", null, h("i", { class: "swatch", style: { background: "var(--attack)" } }), "gerade aktiver Angreifer (Linie zum Honeypot)"),
        h("span", null, h("i", { class: "swatch", style: { background: "var(--good)", borderRadius: "50%" } }), home.label || "Honeypot"))),
    h("aside", { class: "card act" }, h("div", { class: "head" }, h("h2", { title: ACTIVE_TITLE }, "Aktiv (15 Min)"), h("div", { class: "grow" }), actCount), actList,
      h("a", { href: "#/attacks", style: { marginTop: "10px", fontSize: "13px" } }, "Alle Angriffe")),
    h("div", { class: "low" },
      card("Verbindungen nach Dienst", timeline(tl)),
      card("Länder", toplist(countries.slice(0, 7), { key: (x) => x.label || x.key, extra: (x) => cc(x.key) })),
      card("Zugangsdaten", toplist(creds.slice(0, 7)), bruteStatsNote(() => route({ quiet: true })))),
    h("div", { class: "more grid" },
      card("Ports", toplist(ports, { key: (x) => `${x.key} · ${svcName(x.label)}` })),
      card("Angreifer-IPs", toplist(ips, { link: (x) => "#/attacker/" + encodeURIComponent(x.key), extra: (x) => cc(x.label) })),
      card("Netzbetreiber", toplist(asns, { key: (x) => `AS${x.key} ${x.label}` }), bruteStatsNote(() => route({ quiet: true }))),
      card("Befehle", toplist(cmds), bruteStatsNote(() => route({ quiet: true }))))));
  el.querySelector(".low .toplist")?.classList.add("heat");
  renderActive();
  actP.then((act) => {
    actLoaded = true;
    noteBrute(act);
    if (act && el.isConnected) {
      map.seedActive(act.attacks); // Linien für Angreifer der letzten 10 Minuten
      for (const a of act.attacks) {
        const cur = active.get(a.id); // Live-Meldungen können schon neuer sein
        if (!cur || cur.last < a.last) active.set(a.id, a);
      }
    }
    if (el.isConnected) renderActive();
  });

  ctx.live((e) => {
    map.track(e); // Puls, Linie aktiver Angreifer, Länderzähler
    if (e.type === "connect") {
      const t = tiles.connect;
      t.n++;
      t.value.textContent = fmtNum(t.n);
    }
  });
  liveAttacks(ctx, (updated) => {
    for (const a of updated.sort((x, y) => x.last - y.last)) if (!a.own && Date.now() - a.last < ACTIVE_MS) upsertActive(a);
  });
  ctx.every(5000, () => { document.querySelectorAll(".alist [data-rel]").forEach((x) => { x.textContent = relTime(Number(x.dataset.rel)); }); });
  ctx.every(30000, () => { if (!document.hidden) renderActive(); });
  ctx.every(120000, () => { if (!document.hidden && location.hash.replace("#", "").replace("/", "") === "" && !openRows.size && !map.zoomed()) route({ quiet: true }); });
}

// ---------- Einzelne Ereignisse ----------

async function viewFeed(el, ctx, query = "") {
  const qp = new URLSearchParams(query.replace(/^\?/, ""));
  // Gemeinsame Filter der Seite "Angriffe" (Zeitraum, Suchsprache, Stufe, Dienst) plus eigene der Ereignisse
  const sf = sharedFromQuery(qp);
  const f = { type: TYPE_NAME[qp.get("type")] ? qp.get("type") : "", q: "", country: "", port: "", hideNoise: store("hideNoise") !== "0", paused: false };
  const body = h("tbody");
  const info = h("span", { class: "muted" });
  const more = h("button", { class: "btn", onclick: () => load(true) }, "Ältere laden");
  const pauseBtn = h("button", { class: "btn", onclick: () => { f.paused = !f.paused; pauseBtn.textContent = f.paused ? "Fortsetzen" : "Pausieren"; } }, "Pausieren");
  let lastId = 0;

  const params = (before) => {
    const p = sharedParams(sf, new URLSearchParams({ limit: "100" }));
    if (f.type) p.set("type", f.type);
    if (f.q) p.set("q", f.q);
    if (f.country) p.set("country", f.country);
    if (f.port) p.set("dst_port", f.port);
    if (f.hideNoise) p.set("hide_noise", "1");
    if (before) p.set("before", String(lastId));
    return p.toString();
  };
  // Zeilen: gleichartige Ereignisse derselben IP direkt hintereinander werden zusammengefasst ("×10")
  let groups = [], shown = 0;
  const sameKind = (a, b) => a.src_ip === b.src_ip && a.type === b.type && a.service === b.service;
  const setInfo = () => { info.textContent = `${plural(shown, "Ereignis", "Ereignisse")} in ${plural(groups.length, "Zeile", "Zeilen")}`; };
  async function load(older) {
    const rows = await api("events?" + params(older));
    if (!older) { body.replaceChildren(); groups = []; shown = 0; }
    for (const e of rows) {
      const last = groups[groups.length - 1];
      if (last && sameKind(last.items[0], e)) {
        last.items.push(e);
        const tr = eventRow(last.items[0], { group: last.items });
        last.tr.replaceWith(tr);
        last.tr = tr;
      } else {
        const g = { items: [e] };
        g.tr = eventRow(e);
        groups.push(g);
        body.append(g.tr);
      }
      shown++;
    }
    if (rows.length) lastId = rows[rows.length - 1].id;
    more.hidden = rows.length < 100;
    setInfo();
  }
  // Suchsprache und Stufe gelten für Angriffe: neue Ereignisse erst nach dem nächsten Laden
  const matches = (e) => !sf.q && !sf.stufe.size && (!sf.service || e.service === sf.service) && (!f.type || e.type === f.type) && !(f.hideNoise && isNoise(e))
    && (!f.country || e.country === f.country) && (!f.port || String(e.dst_port) === f.port)
    && (!f.q || JSON.stringify(e).toLowerCase().includes(f.q.toLowerCase()));

  const sel = (opts, key, label) => h("select", { "aria-label": label, onchange: (e) => { f[key] = e.target.value; load(); } },
    h("option", { value: "" }, label), opts.map(([v, l]) => h("option", { value: v, selected: f[key] === v }, l)));
  let qTimer;
  // Export mit den aktuellen Filtern (Download über den angemeldeten Browser)
  const exRange = h("select", { "aria-label": "Zeitraum für den Export" },
    [["24h", "24 Std"], ["7d", "7 Tage"], ["30d", "30 Tage"], ["90d", "90 Tage"]].map(([v, l]) => h("option", { value: v, selected: v === "7d" }, l)));
  // Export: eigener Zeitraum; Dienst, Typ, Text, Land und Port wie in der Liste
  const exParams = (format) => { const p = new URLSearchParams(params()); p.delete("aq"); p.delete("stufe"); p.delete("limit"); p.set("range", exRange.value); p.set("format", format); return p; };
  const download = (path) => { const a = h("a", { href: path, download: "" }); document.body.append(a); a.click(); a.remove(); };
  const exportBox = h("div", { class: "filters" },
    h("span", { class: "muted" }, "Export:"), exRange,
    h("button", { class: "btn small", onclick: () => download(`api/export/events?${exParams("csv")}`) }, "CSV"),
    h("button", { class: "btn small", onclick: () => download(`api/export/events?${exParams("json")}`) }, "JSON"),
    h("button", { class: "btn small", title: "Öffentliche Angreifer-IPs, eine pro Zeile (z. B. für Firewall-Regeln)", onclick: () => download(`api/export/blocklist?range=${exRange.value}`) }, "Blockliste"),
    h("button", { class: "btn small", title: "Angreifer-IPs, Nachlade-Adressen und Datei-Hashes als STIX 2.1 (für MISP, OpenCTI, Firewalls)", onclick: () => download(`api/export/stix?range=${exRange.value}`) }, "STIX"));
  header("Angriffe", { extra: [viewSwitch("einzeln", () => sharedQS(sf)), sharedRange(sf, () => load()), pauseBtn] });
  mount(el, h("div", { class: "stack" },
    sharedBar(sf, () => load(), info, SERVICES),
    h("div", { class: "filters" },
      sel(Object.entries(TYPE_NAME), "type", "Alle Typen"),
      h("input", { type: "search", placeholder: "Text in Ereignissen: Passwort, Befehl …", oninput: (e) => { clearTimeout(qTimer); qTimer = setTimeout(() => { f.q = e.target.value.trim(); load(); }, 350); } }),
      h("input", { "aria-label": "Land", placeholder: "Land (z. B. CN)", maxlength: 3, style: { width: "120px" }, onchange: (e) => { f.country = e.target.value.trim().toUpperCase(); e.target.value = f.country; load(); } }),
      h("input", { "aria-label": "Port", type: "number", placeholder: "Port", min: 1, max: 65535, style: { width: "90px" }, onchange: (e) => { f.port = e.target.value.trim(); load(); } }),
      h("label", { class: "inline", title: "Verbindungen aus eigenen Netzen (Einstellungen → Eigene Netze); wie auf der Seite „Angriffe“ standardmäßig ausgeblendet" },
        h("input", { type: "checkbox", checked: sf.own, onchange: (e) => { sf.own = e.target.checked; load(); } }), "Eigene Tests zeigen"),
      h("label", { class: "inline" }, h("input", { type: "checkbox", checked: f.hideNoise, onchange: (e) => { f.hideNoise = e.target.checked; store("hideNoise", f.hideNoise ? "1" : "0"); load(); } }), "Verbindungsauf- und -abbau ausblenden")),
    exportBox,
    card(null, h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Zeit", "Dienst", "Typ", "Quelle", "Details"].map((t) => h("th", null, t)))), body))),
    more));
  await load();
  ctx.live((e) => {
    if (f.paused || (e.own && !sf.own) || !matches(e)) return;
    const first = groups[0];
    shown++;
    if (first && sameKind(first.items[0], e)) {
      first.items.unshift(e);
      const tr = eventRow(e, { group: first.items, fresh: true });
      first.tr.replaceWith(tr);
      first.tr = tr;
    } else {
      const g = { items: [e], tr: eventRow(e, { fresh: true }) };
      groups.unshift(g);
      body.prepend(g.tr);
      while (groups.length > 1000) groups.pop().tr.remove();
    }
    setInfo();
  });
}

// ---------- Sitzungen ----------

async function viewSessions(el, ctx, query = "") {
  // Gemeinsame Filter der Seite "Angriffe" (hive/attackfilter.go); Stufe und Art kommen vom Angriff
  const sf = sharedFromQuery(new URLSearchParams(query.replace(/^\?/, "")));
  const box = h("div");
  const info = h("span", { class: "muted" });
  const yes = (n, cls = "") => (n ? h("span", { class: "badge " + cls }, fmtNum(n)) : h("span", { class: "muted" }, "–"));
  const stufeOf = (r) => (r.downloads ? 4 : r.commands ? 3 : r.success ? 2 : 1);
  async function load() {
    mount(box, h("p", { class: "muted" }, "Lade …"));
    const rows = await api("sessions?" + sharedParams(sf));
    if (!ctx.current()) return;
    info.textContent = plural(rows.length, "Sitzung", "Sitzungen") + (rows.length >= 200 ? " (die neuesten 200)" : "");
    mount(box, card(null, rows.length ? h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Start", "Dienst", "Quelle", "Stufe", "Art", "Logins", "Befehle", "Was getippt wurde", "Dauer", "Status"].map((t) => h("th", null, t)))),
      h("tbody", null, rows.map((r) => {
        const st = stufeOf(r);
        return h("tr", { class: "click", onclick: (e) => { if (!e.target.closest("a")) location.hash = "#/session/" + encodeURIComponent(r.session); } },
          h("td", { class: "num", style: { whiteSpace: "nowrap" } }, fmtDateTime(r.start)),
          h("td", null, svcBadge(r.service, r.dst_port)),
          h("td", { style: { whiteSpace: "nowrap" } }, ipLink(r.src_ip), " ", cc(r.country)),
          h("td", null, h("span", { class: "badge stufe", style: { "--c": `var(--sev${st})` } }, STUFE[st])),
          h("td", { style: { whiteSpace: "nowrap" } }, r.profile || h("span", { class: "muted" }, "–")),
          h("td", null, yes(r.logins)), h("td", null, yes(r.commands)),
          h("td", { class: "det mono", title: (r.cmds || []).join("\n") }, (r.cmds || []).join(" ⏎ ") || h("span", { class: "muted" }, "–")),
          h("td", { class: "num" }, fmtDur(r.last - r.start)),
          h("td", null, r.success ? h("span", { class: "badge ok" }, "Login erfolgreich") : null, r.downloads ? h("span", { class: "badge err" }, plural(r.downloads, "Datei", "Dateien")) : null,
            r.tarpit ? h("span", { class: "badge tarpit" }, "festgehalten") : null));
      }))))
      : h("div", { class: "empty" }, "Keine Sitzungen mit Logins, Befehlen oder Dateien für diese Auswahl.")));
  }
  header("Angriffe", { extra: [viewSwitch("sitzungen", () => sharedQS(sf)), sharedRange(sf, () => load())] });
  mount(el, h("div", { class: "stack" },
    sharedBar(sf, () => load(), info, SERVICES),
    h("p", { class: "sub" }, "Einzelne Verbindungen, in denen sich ein Angreifer angemeldet, Befehle getippt oder Dateien geladen hat. Klick öffnet den Ablauf mit Angriffsbericht und, bei Cowrie, dem Terminal-Mitschnitt."),
    box));
  await load();
}

async function viewSession(el, ctx, id) {
  header("Sitzung " + id);
  const evs = await api("sessions/" + encodeURIComponent(id));
  if (!evs.length) { mount(el, h("div", { class: "empty" }, "Sitzung nicht gefunden (evtl. schon aufgeräumt).")); return; }
  const f = evs[0], start = toMs(f.ts), end = toMs(evs[evs.length - 1].ts);
  const line = (e) => {
    const d = parseData(e);
    const t = h("span", { class: "t" }, "+" + fmtDur(toMs(e.ts) - start));
    if (e.type === "command") return h("div", null, t, h("span", { class: "cmd" }, d.input || ""));
    return h("div", { class: "info" }, t, `[${TYPE_NAME[e.type] || e.type}] `, describe(e));
  };
  const sessChain = chainCard({ session: id });
  let chainT = 0;
  ctx.live((e) => { if (e.session === id) { clearTimeout(chainT); chainT = setTimeout(() => sessChain.refresh(), 2000); } });
  mount(el, h("div", { class: "stack" },
    h("div", { class: "grid kpi" },
      tile("Quelle", h("span", null, ipLink(f.src_ip)), [f.city, f.country_name].filter(Boolean).join(", ")),
      tile("Dienst", svcName(f.service), "Port " + f.dst_port),
      tile("Beginn", fmtDateTime(start)), tile("Dauer", fmtDur(end - start))),
    sessChain,
    reportCard({ session: id }),
    evs.some((e) => e.type === "tty") ? ttyCard(id) : null,
    card("Ablauf", h("div", { class: "term" }, evs.map(line)))));
}

// ---------- Angreifer ----------

async function viewAttacker(el, ctx, ip) {
  header("Angreifer");
  const [d, at] = await Promise.all([api("attackers/" + encodeURIComponent(ip)), api(`attacks?range=all&limit=200&own=1&ip=${encodeURIComponent(ip)}`).catch(() => null)]);
  const i = d.info;
  noteBrute(at);
  noteBrute(d);
  const attacks = at ? at.attacks : [];
  const top = attacks.reduce((m, a) => (a.stufe > m ? a.stufe : m), 0);
  const fact = (k, v) => h("div", null, h("div", { class: "k" }, k), h("div", { class: "v num" }, v));
  const openCards = new Set();
  // Ab dem 4. Angriff: Zusammenfassung über alle Angriffe zuerst (attacks.js, historyView)
  const hist = d.history || null;
  const nAttacks = hist ? Math.max(hist.attacks, attacks.length) : attacks.length;
  const list = h("div", { class: "feed" });
  const renderList = (freshId) => mount(list, !attacks.length
    ? h("div", { class: "empty" }, "Keine Angriffe in den gespeicherten Rohdaten (ältere sind nach der Aufbewahrungszeit gelöscht).")
    : hist && nAttacks >= HISTORY_FROM ? historyView(hist, attacks, { open: openCards })
      : attacks.map((x, k) => { x.seen = nAttacks - k; return attackCard(x, { showIP: false, open: openCards, fresh: x.id === freshId }); }));
  renderList();
  const chain = chainCard({ ip });
  mount(el, h("div", { class: "stack" },
    h("section", { class: "card" },
      h("div", { class: "hero" },
        flag(i.country) || h("span", { class: "flag" }, "🏳"),
        h("div", null,
          h("div", { class: "t1 mono" }, ip),
          h("div", { class: "t2" }, [[i.city, i.country_name || i.country].filter(Boolean).join(", ") || "Herkunft unbekannt", i.asn ? `AS${i.asn} ${i.as_org || ""}` : ""].filter(Boolean).join(" · "))),
        h("div", { class: "grow" }),
        attacks.length ? h("span", { class: "badge stufe", style: { "--c": `var(--sev${top})` } }, "Höchste Stufe: ", ["Abtasten", "Versuche", "Login angenommen", "Befehle ausgeführt", "Datei nachgeladen"][top]) : null,
        attacks.some((a) => (a.ai_replies || []).length) ? h("span", { class: "badge ai", title: "Das Sprachmodell hat dieser IP geantwortet; Einzelheiten in den Angriffen und im Bericht" }, "beantwortet durch KI") : null,
        attacks.some((a) => a.brute) || d.condensed ? h("span", { class: "badge", title: BRUTE_TITLE }, "Dauer-Brute-Force") : null,
        activeBadge(i.last_seen)),
      h("div", { class: "facts-row" },
        fact("Erstmals gesehen", fmtDateTime(i.first_seen)), fact("Zuletzt gesehen", relTime(i.last_seen)),
        fact("Angriffe", fmtNum(nAttacks)), fact("Ereignisse", fmtNum(i.events)),
        fact("Login-Versuche", fmtNum(i.logins)), fact("Befehle", fmtNum(i.commands)), fact("Tarpit-Zeit", fmtDur(i.tarpit_ms)),
        d.condensed ? fact("Davon verdichtet", fmtNum(d.condensed)) : null),
      d.condensed ? h("p", { class: "muted", style: { margin: "8px 0 0" } }, BRUTE_TITLE) : null),
    relatedCard(d),
    h("section", { class: "card" }, h("div", { class: "head" }, h("h2", null, "Angriffe dieser IP"), h("div", { class: "grow" }),
      hist && nAttacks >= HISTORY_FROM ? h("span", { class: "hint" }, `${fmtNum(nAttacks)} Angriffe · ${fmtDateTime(hist.first)} bis ${fmtDateTime(hist.last)}`) : null), list),
    h("div", { class: "grid two" },
      card("Angegriffene Ports", toplist(d.ports.map((p) => ({ key: `${p.dst_port} · ${svcName(p.service)}`, n: p.n })))),
      card("Benutzte Zugangsdaten", toplist(d.creds.map((c) => ({ key: credText(`${c.username} / ${c.password}`), n: c.n }))))),
    chain,
    reportCard({ ip }),
    intelCard(ip),
    h("section", { class: "card" }, panels([{ label: "Alle Ereignisse einzeln", count: d.events.length, body: () => evTable(d.events, { showIP: false }) }]))));
  liveAttacks(ctx, (updated) => {
    const a = updated.find((x) => x.ip === ip);
    if (!a) return;
    chain.refresh(); // Angriffskette unauffällig nachziehen
    const n = attacks.findIndex((x) => x.id === a.id);
    if (n >= 0) attacks.splice(n, 1);
    attacks.unshift(a);
    renderList(a.id);
  });
}

// "Gehört vermutlich zu …": andere IPs derselben Gruppe mit Begründung (hive/related.go)
const RELATED_RULES = "Zusammengefasst wird nur bei derselben Zugangsdatenliste (mindestens 10 Kombinationen), derselben Nachlade-Adresse oder Wallet, " +
  "oder bei einem seltenen Fingerabdruck (HASSH, JA4, HTTP), derselben Befehlsfolge oder denselben ersten 20 Zugangsdaten in derselben Reihenfolge zusammen mit demselben Netz (/24) oder Netzbetreiber. " +
  "Gleiches Netz, gleicher Netzbetreiber oder zeitliche Nähe allein genügen nie; Forschungsscanner und eigene Tests bleiben außen vor. Grundlage: die letzten 7 Tage.";
function relatedCard(d) {
  if (!d.group || !(d.related || []).length) return null;
  return h("section", { class: "card", id: "gruppe" },
    h("div", { class: "head" }, h("h2", null, `Gehört vermutlich zu ${d.related.length === 1 ? "einer weiteren IP" : d.related.length + " weiteren IPs"}`)),
    h("p", { class: "sub" }, RELATED_RULES),
    h("div", { class: "list" }, d.related.slice(0, 30).map((r) => h("div", { class: "related-row" },
      h("a", { class: "mono", href: "#/attacker/" + encodeURIComponent(r.ip) }, r.ip),
      h("span", { class: "muted" }, (r.reasons || []).length ? r.reasons.join(" · ") : "über weitere IPs der Gruppe verbunden")))),
    d.group.n_ips > 31 ? h("p", { class: "muted" }, `… und ${fmtNum(d.group.n_ips - 31)} weitere.`) : null);
}

// ---------- System ----------

// Updates: Version, Kanal (fertige Versionen oder auch Vorabversionen), "Jetzt prüfen"
// und, wo ein Updater eingerichtet ist (Raspberry-Pi-Image), "Jetzt aktualisieren".
function updateCard(u) {
  const admin = state.user && state.user.role === "admin";
  const body = h("div");
  const msg = h("div", { class: "msg", hidden: true });
  const say = (text, ok) => { msg.className = "msg " + (ok ? "ok" : "err"); msg.textContent = text; msg.hidden = false; };
  const validDate = (t) => toMs(t) > 0 && new Date(t).getFullYear() > 2000;

  function render(st) {
    const rows = [
      ["Installiert", st.current || "–"],
      ["Kanal", admin ? h("select", {
        "aria-label": "Update-Kanal",
        onchange: async (e) => {
          e.target.disabled = true;
          try { render(await api("update/channel", { method: "PUT", body: { channel: e.target.value } })); say("Kanal gespeichert.", true); }
          catch (ex) { say(ex.message, false); e.target.disabled = false; }
        },
      },
      h("option", { value: "stable", selected: st.channel !== "pre" }, "Stabil (nur fertige Versionen)"),
      h("option", { value: "pre", selected: st.channel === "pre" }, "Vorabversionen (Pre-Release, zum Testen)"))
        : (st.channel === "pre" ? "Vorabversionen" : "Stabil")],
      ["Zuletzt geprüft", st.check_enabled === false ? st.disabled_reason : validDate(st.checked) ? relTime(st.checked) : "noch nicht"],
      ["Ergebnis", st.error ? h("span", { class: "badge err", title: st.error }, "Prüfung fehlgeschlagen")
        : st.available ? h("a", { href: st.available.url, target: "_blank", rel: "noopener noreferrer" }, `Version ${st.available.version} verfügbar`)
          : validDate(st.checked) ? h("span", { class: "badge ok" }, "aktuell") : "–"],
      st.last_run ? ["Letztes Update", st.last_run] : null,
    ];
    const checkBtn = admin && st.check_enabled !== false ? h("button", {
      class: "btn",
      onclick: async () => {
        checkBtn.disabled = true;
        checkBtn.textContent = "Prüfe …";
        try {
          const n = await api("update/check", { method: "POST" });
          render(n);
          say(n.error ? "GitHub nicht erreichbar oder Repository nicht öffentlich: " + n.error
            : n.available ? `Version ${n.available.version} ist verfügbar.` : "Du hast die neueste Version.", !n.error);
        } catch (ex) { say(ex.message, false); checkBtn.disabled = false; checkBtn.textContent = "Jetzt prüfen"; }
      },
    }, "Jetzt prüfen") : null;
    const installBtn = admin && st.can_install && st.available ? h("button", {
      class: "btn primary",
      onclick: async () => {
        if (!confirm(`Jetzt auf Version ${st.available.version} aktualisieren? Die Dienste starten dabei neu.`)) return;
        installBtn.disabled = true;
        try {
          await api("update", { method: "POST" });
          say("Update läuft. Die Seite lädt in etwa zwei Minuten neu.", true);
          setTimeout(() => location.reload(), 120000);
        } catch (ex) { say(ex.message, false); installBtn.disabled = false; }
      },
    }, `Auf ${st.available.version} aktualisieren`) : null;
    mount(body,
      h("table", null, h("tbody", null, rows.filter(Boolean).map(([k, v]) => h("tr", null, h("th", null, k), h("td", null, v))))),
      h("div", { class: "filters", style: { marginTop: "10px" } }, checkBtn, installBtn,
        !st.can_install ? h("span", { class: "muted" }, "Docker-Betrieb: aktualisieren mit „sh update.sh“.") : null));
  }
  render(u);
  return card("Updates", body, msg,
    h("p", { class: "muted" }, "Vorabversionen bringen neue Funktionen früher, können aber Fehler enthalten. Automatisch geprüft wird zweimal täglich."));
}

// Zeilen zur Größengrenze der Datenbank (dblimit.go) für die Karte „Hive“.
function dbLimitRows(d) {
  if (!d) return [];
  const last = (d.grow_log || [])[0];
  const full = d.auto_grow && d.at_ceiling ? h("span", { class: "warn-text" }, `Obergrenze ${fmtBytes(d.ceiling)} erreicht`)
    : d.auto_grow ? `automatisch bis ${fmtBytes(d.ceiling)}` : `aus (möglich bis ${fmtBytes(d.ceiling)})`;
  return [
    ["Grenze", h("span", { title: d.ceiling_reason }, d.source === "setting" ? "eingestellt" : "Vorgabe HIVE_MAX_DB_MB", " · Erweiterung ", full)],
    last ? ["Zuletzt erweitert", `Grenze automatisch auf ${fmtBytes(last.to)} erhöht am ${fmtDateTime(last.at)}`] : null,
    ["Wenn sie voll ist", "Der Hive löscht die ältesten Ereignisse; Statistiken ohne IPs bleiben. Ändern unter Einstellungen → Daten."],
  ];
}

async function viewSystem(el, ctx) {
  header("System");
  const [d, hw] = await Promise.all([api("system"), api("hardware").catch(() => null)]);
  const hv = d.hive;
  const kv = (rows) => h("table", null, h("tbody", null, rows.filter(Boolean).map(([k, v]) => h("tr", null, h("th", null, k), h("td", null, v)))));
  const sensorOk = (s) => Date.now() - toMs(s.seen) < 60000;
  const validDate = (t) => toMs(t) > 0 && new Date(t).getFullYear() > 2000;
  const egressBadge = (e) => (e === "gesperrt" ? h("span", { class: "badge ok" }, "gesperrt")
    : e === "offen" ? h("span", { class: "badge err" }, "offen – Netzsperre fehlt") : h("span", { class: "badge" }, e || "unbekannt"));
  const vols = d.cowrie.volumes || {};
  mount(el, h("div", { class: "stack" },
    warningsBox(d.warnings, false) || h("div", { class: "msg ok" }, "Keine Warnungen."),
    hw ? hardwareCard(hw) : null,
    updateCard(d.update || {}),
    h("div", { class: "grid three" },
      card("Hive", kv([
        ["Version", hv.version], ["Läuft seit", fmtDur(hv.uptime_s * 1000)], ["Arbeitsspeicher", fmtBytes(hv.mem_bytes)],
        ["Datenbank", `${fmtBytes(hv.db_used_bytes)} belegt, Grenze ${fmtBytes(hv.max_db_bytes)}`],
        ...dbLimitRows(hv.db_limit),
        ["Freier Speicher", hv.disk_free >= 0 ? fmtBytes(hv.disk_free) : "–"],
        ["Gespeicherte Ereignisse", fmtNum(hv.events_stored)], ["Bekannte Angreifer-IPs", fmtNum(hv.attackers)],
        ["Seit Start geschrieben", fmtNum(hv.written)], ["Duplikate verworfen", fmtNum(hv.duplicates)],
        ["Nicht gespeichert", hv.dropped ? h("span", { class: "badge err" }, fmtNum(hv.dropped)) : "0"],
        ["Warteschlange", fmtNum(hv.queue)], ["Aufbewahrung", hv.retention_days + " Tage"],
        ["Letztes Aufräumen", hv.retention && validDate(hv.retention.last_run) ? relTime(hv.retention.last_run) : "noch nicht"],
        ["Benachrichtigungen", d.notify ? `${fmtNum(d.notify.sent)} gesendet, ${fmtNum(d.notify.suppressed)} unterdrückt` : "–"],
        d.notify && d.notify.last_error ? ["Letzter Sendefehler", h("span", { class: "warn-text" }, d.notify.last_error)] : null])),
      card("GeoIP", kv([["Status", d.geoip.status], ["Stand", validDate(d.geoip.updated) ? fmtDateTime(d.geoip.updated) : "–"],
        ["Quelle", h("a", { href: "https://db-ip.com", target: "_blank", rel: "noopener noreferrer" }, "IP-Geodaten von DB-IP.com (CC BY 4.0)")]])),
      card("Cowrie (SSH/Telnet)", kv(d.cowrie.enabled ? [
        ["Log-Datei", d.cowrie.found ? h("span", { class: "badge ok" }, "gefunden") : h("span", { class: "badge err" }, "fehlt")],
        ["Letztes Ereignis", relTime(d.cowrie.last_event)],
        vols.log !== undefined ? ["Logs", fmtBytes(vols.log)] : null,
        vols.lib !== undefined ? ["Downloads und Mitschnitte", fmtBytes(vols.lib)] : null,
        d.cowrie.install ? ["Installation", installBadge(d.cowrie.install)] : null,
        ...(d.cowrie.ports || []).map((p) => [p.name === "ssh" ? "SSH-Port" : "Telnet-Port",
          p.ok ? h("span", { class: "badge ok", title: "geprüft " + relTime(p.checked) }, "lauscht")
            : h("span", { class: "badge err", title: p.error || "" }, "lauscht nicht" + (p.hint ? ": " + p.hint : ""))])]
        : [["Status", "nicht eingerichtet"]]))),
    d.network ? networkCard(d.network) : null,
    d.sensors.length ? d.sensors.map((s) => card("Sensor " + s.sensor,
      h("div", { class: "grid three" },
        kv([["Status", sensorOk(s) ? h("span", { class: "badge ok" }, "verbunden") : h("span", { class: "badge err" }, "keine Meldung")],
          ["Letzte Meldung", relTime(s.seen)], ["Version", s.version], ["Läuft seit", fmtDur(s.uptime_s * 1000)],
          ["Internet aus dem Container", egressBadge(s.egress)]]),
        kv([["Arbeitsspeicher", fmtBytes(s.mem_bytes)], ["Offene Verbindungen", fmtNum(s.connections)], ["Davon festgehalten", fmtNum(s.tarpits)],
          ["Abgewiesen (Limit)", fmtNum(s.conns_rejected)],
          ["Aus eigenem Docker-Netz", s.proxied_conns ? h("span", { class: "badge err", title: "Echte Angreifer-IPs gehen vermutlich verloren, siehe README" }, fmtNum(s.proxied_conns)) : "0"]]),
        kv([["Gesendete Ereignisse", fmtNum(s.events_sent)], ["Gedrosselt (pro IP)", fmtNum(s.events_throttled)], ["Verworfen", fmtNum(s.events_dropped)], ["Letzter Fehler", s.last_error || "keiner"]])),
      h("h3", null, "Ports"),
      h("div", { class: "tablewrap" }, h("table", null,
        h("thead", null, h("tr", null, ["Port", "Dienst", "Modus", "Status", "Offen", "Verbindungen seit Start", "Abgewiesen"].map((t) => h("th", null, t)))),
        h("tbody", null, (s.listeners || []).map((l) => h("tr", null,
          h("td", { class: "num" }, l.port), h("td", null, svcName(l.service)), h("td", null, MODE_NAME[l.mode] || l.mode),
          h("td", null, l.running ? h("span", { class: "badge ok" }, "läuft") : h("span", { class: "badge err", title: l.error || "" }, l.error ? "Fehler: " + l.error : "aus")),
          h("td", { class: "num" }, fmtNum(l.active)), h("td", { class: "num" }, fmtNum(l.total)), h("td", { class: "num" }, fmtNum(l.rejected || 0)))))))))
      : card("Sensoren", h("div", { class: "empty" }, "Noch kein Sensor hat sich gemeldet.")),
    exposureCard()));
  ctx.every(15000, () => { if (!document.hidden && location.hash === "#/system" && ctx.current() && !document.activeElement?.closest?.("form, select, input, textarea")) route({ quiet: true }); });
}

// Netzsperre und Verwaltungsanschluss auf dem Pi (USB-Adapter ins Heimnetz, nur Web-UI)
function networkCard(n) {
  const fw = !n.supported ? h("span", { class: "badge" }, "nicht verfügbar (älteres Image)")
    : !n.firewall ? h("span", { class: "badge err" }, "keine Rückmeldung")
    : h("span", null, h("span", { class: "badge " + (n.firewall.state === "ok" ? "ok" : "err") }, n.firewall.state === "ok" ? "aktiv" : "Fehler"),
      " ", n.firewall.text, " · ", relTime(n.firewall.since));
  const rows = [["Netzsperre", fw]];
  if (!n.mgmt || !n.mgmt.length) {
    rows.push(["Verwaltungsanschluss", "keiner"]);
  } else {
    for (const m of n.mgmt) {
      rows.push(["Verwaltungsanschluss " + m.name, h("span", null,
        h("span", { class: "badge " + (m.up ? "ok" : "") }, m.up ? "verbunden" : "getrennt"),
        m.addrs.length ? " " + m.addrs.join(", ") : "")]);
    }
  }
  return card("Netzwerk", h("table", null, h("tbody", null, rows.map(([k, v]) => h("tr", null, h("th", null, k), h("td", null, v))))),
    h("p", { class: "muted" }, "Ein USB-Netzwerkadapter im Heimnetz dient als Verwaltungsanschluss: Darüber ist nur die Web-UI (Port 8088) erreichbar, "
      + "der Pi baut dort selbst keine Verbindung auf. Honeypot und Internet laufen über den eingebauten Anschluss (Gastnetz)."));
}

// Stand der Cowrie-Installation auf dem Pi (Datei von hivornet-cowrie-install)
function installBadge(ci) {
  const cls = ci.state === "ok" ? "ok" : ci.state === "failed" ? "err" : "";
  const label = ci.state === "ok" ? "fertig" : ci.state === "failed" ? "gescheitert" : "läuft";
  return h("span", null, h("span", { class: "badge " + cls }, label), " ", ci.text, " · ", relTime(ci.since),
    state.user.logs ? h("span", null, " · ", h("a", { href: "#/logs?cowrie-install" }, "Protokoll")) : null);
}

// ---------- Protokolle (nur Raspberry Pi, nur Admins) ----------

const ANSI = /\x1b\[[0-9;?]*[A-Za-z]/g;

async function viewLogs(el, ctx) {
  header("Protokolle");
  const d = await api("logs");
  if (!d.enabled) {
    mount(el, card("Protokolle", h("div", { class: "empty" }, "Protokolle gibt es nur auf dem Raspberry Pi. Im Docker-Betrieb: docker compose logs.")));
    return;
  }
  const want = (location.hash.split("?")[1] || store("logsrc") || "cowrie-install");
  const src = h("select", { "aria-label": "Quelle" }, d.sources.map((s) => h("option", { value: s.id, selected: s.id === want }, s.label)));
  const lines = h("select", { "aria-label": "Zeilen" }, [100, 200, 500, 1000, 2000].map((n) => h("option", { value: n, selected: n === 200 }, n + " Zeilen")));
  const follow = h("input", { type: "checkbox", checked: true });
  const out = h("pre", { class: "log" }, "Lade …");
  const info = h("span", { class: "muted" });
  let busy = false;
  async function load() {
    if (busy) return;
    busy = true;
    store("logsrc", src.value);
    const atEnd = out.scrollTop + out.clientHeight >= out.scrollHeight - 30;
    try {
      const r = await api("logs/" + encodeURIComponent(src.value) + "?lines=" + lines.value);
      out.textContent = r.text.replace(ANSI, "");
      info.textContent = "Stand " + new Date().toLocaleTimeString("de-DE");
      if (atEnd || out.dataset.first !== "0") { out.scrollTop = out.scrollHeight; out.dataset.first = "0"; }
    } catch (e) {
      out.textContent = "Fehler: " + e.message;
    } finally { busy = false; }
  }
  src.onchange = () => { out.dataset.first = "1"; load(); };
  lines.onchange = load;
  mount(el, h("div", { class: "stack" },
    card("Systemprotokolle",
      h("p", { class: "sub" }, "Nur lesen. Neueste Einträge unten. Die Anmeldung am Pi selbst ist absichtlich gesperrt; hier steht, was die Hivornet-Dienste melden."),
      h("div", { class: "filters" }, src, lines,
        h("label", { class: "inline" }, follow, "alle 5 s aktualisieren"),
        h("button", { class: "btn small", onclick: load }, "Aktualisieren"), info),
      out)));
  await load();
  ctx.every(5000, () => { if (follow.checked && !document.hidden && ctx.current()) load(); });
}

// Bausteine für extra.js. Die beiden Module importieren sich gegenseitig; das ist
// in Ordnung, weil extra.js diese Namen nur innerhalb von Funktionen benutzt.
export { state, header, card, tile, cc, ipLink, svcBadge, describe, isNoise, TYPE_NAME, MODE_NAME, route, rangePicker, rangeOK, loadDashboard, warningsBox, NAV };

boot();
