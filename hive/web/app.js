// Hivornet Web-UI: Anmeldung, Navigation und alle Ansichten.
import {
  h, mount, api, AuthError, fmtNum, fmtBytes, fmtDur, fmtTime, fmtDateTime, relTime, toMs, store,
} from "./dom.js";
import { worldMap, timeline, toplist, svcName, svcColor } from "./charts.js";

const app = document.getElementById("app");
const state = { user: null, range: store("range") || "24h", es: null, liveFns: new Set(), cleanup: null };

const NAV = [
  ["#/", "Dashboard"], ["#/feed", "Live-Feed"], ["#/sessions", "Sitzungen"], ["#/creds", "Zugangsdaten"],
  ["#/tarpit", "Tarpit"], ["#/settings", "Einstellungen"], ["#/system", "System"],
];
const RANGES = [["24h", "24 Std"], ["7d", "7 Tage"], ["30d", "30 Tage"]];
const TYPE_NAME = {
  connect: "Verbindung", disconnect: "Ende", login: "Login", request: "Anfrage", command: "Befehl",
  download: "Download", client_version: "Client", payload: "Daten", tls: "TLS", fingerprint: "Fingerabdruck",
};
// Muss alle Dienste des Honeypots enthalten (Test TestServiceListsInSync im Honeypot).
const SERVICES = ["ssh", "telnet", "http", "https", "ftp", "smtp", "redis", "mysql", "dockerapi", "rdp", "vnc", "ssh-tarpit", "raw"];
const MODE_NAME = { emulate: "Aufzeichnen", tarpit: "Tarpit", hybrid: "Hybrid" };

// ---------- Theme ----------
function applyTheme(t) {
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
}
applyTheme(store("theme"));

// ---------- Start, Anmeldung ----------

async function boot() {
  try { state.user = await api("me", { noAuthRedirect: true }); } catch { state.user = null; }
  if (!state.user) return showLogin();
  renderShell();
  startStream();
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
  mount(app, h("div", { class: "login" }, form));
  pass.focus();
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
function stopStream() { if (state.es) state.es.close(); state.es = null; }
function setLive(on) {
  const d = document.getElementById("live");
  if (d) { d.classList.toggle("on", on); d.lastChild.textContent = on ? "live" : "getrennt"; }
}
function onLive(fn) { state.liveFns.add(fn); return () => state.liveFns.delete(fn); }

// ---------- Rahmen und Router ----------

let mainEl, topEl;

function renderShell() {
  const theme = h("select", {
    "aria-label": "Darstellung",
    onchange: (e) => { store("theme", e.target.value); applyTheme(e.target.value); },
  }, [["auto", "System"], ["dark", "Dunkel"], ["light", "Hell"]].map(([v, l]) => h("option", { value: v, selected: (store("theme") || "auto") === v }, l)));
  mainEl = h("div");
  topEl = h("div", { class: "top" });
  mount(app, h("div", { class: "shell" },
    h("aside", { class: "side" },
      h("div", { class: "brand" }, h("img", { src: "favicon.svg", alt: "" }), "Hivornet"),
      h("nav", { class: "nav" }, NAV.map(([href, label]) => h("a", { href }, label))),
      h("div", { class: "grow" }),
      h("div", { class: "foot" },
        h("span", { id: "live", class: "live-dot" }, h("i"), h("span", null, "verbinde …")),
        h("span", null, "Angemeldet als ", state.user.username),
        theme,
        h("button", { class: "btn small", onclick: logout }, "Abmelden"),
        h("span", null, "Version ", state.user.version))),
    h("main", { class: "main" }, topEl, mainEl)));
  window.onhashchange = route;
}

function header(title, { range = false, extra = null } = {}) {
  const seg = range ? h("div", { class: "seg", role: "group", "aria-label": "Zeitraum" },
    RANGES.map(([v, l]) => h("button", {
      class: state.range === v ? "on" : "", onclick: () => { state.range = v; store("range", v); route(); },
    }, l))) : null;
  mount(topEl, h("h1", null, title), h("div", { class: "grow" }), extra, seg);
}

const routes = [
  [/^#?\/?$/, viewDashboard], [/^#\/feed$/, viewFeed], [/^#\/sessions$/, viewSessions],
  [/^#\/session\/(.+)$/, viewSession], [/^#\/attacker\/(.+)$/, viewAttacker], [/^#\/creds$/, viewCreds],
  [/^#\/tarpit$/, viewTarpit], [/^#\/settings$/, viewSettings], [/^#\/system$/, viewSystem],
];

async function route() {
  if (!mainEl) return;
  if (state.cleanup) { state.cleanup(); state.cleanup = null; }
  const hash = location.hash || "#/";
  for (const a of document.querySelectorAll(".nav a")) {
    const href = a.getAttribute("href");
    a.classList.toggle("on", href === "#/" ? hash === "#/" || hash === "" : hash.startsWith(href));
  }
  const [, view, m] = routes.map(([re, v]) => [re, v, hash.match(re)]).find(([, , m]) => m) || [null, viewDashboard, []];
  // Jede Ansicht zeichnet in ihren eigenen Behälter. Wird inzwischen weiternavigiert,
  // landet eine verspätete Ansicht in einem Behälter, der nicht mehr angezeigt wird,
  // und ihre Live-Handler und Timer werden sofort wieder abgeräumt.
  const seq = ++routeSeq;
  const host = h("div", null, h("p", { class: "muted" }, "Lade …"));
  mount(mainEl, host);
  const cleanups = [];
  const cleanupAll = () => cleanups.splice(0).forEach((f) => f());
  state.cleanup = cleanupAll;
  try {
    const ctx = {
      live: (fn) => cleanups.push(onLive(fn)),
      every: (ms, fn) => { const t = setInterval(fn, ms); cleanups.push(() => clearInterval(t)); },
      current: () => seq === routeSeq,
    };
    await view(host, ctx, ...(m || []).slice(1).map(decodeURIComponent));
    if (seq !== routeSeq) cleanupAll();
  } catch (e) {
    cleanupAll();
    if (seq !== routeSeq) return;
    if (e instanceof AuthError) return showLogin("Bitte erneut anmelden.");
    mount(host, h("div", { class: "msg err" }, "Fehler: " + e.message));
  }
}
let routeSeq = 0;

// ---------- gemeinsame Bausteine ----------

const card = (title, ...kids) => h("section", { class: "card" }, title ? h("div", { class: "head" }, h("h2", null, title)) : null, ...kids);
const tile = (label, value, hint) => h("div", { class: "card tile" }, h("div", { class: "label" }, label), h("div", { class: "value num" }, value), hint ? h("div", { class: "hint" }, hint) : null);
const cc = (code, name) => (code ? h("span", { class: "badge cc", title: name || code }, code) : null);
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
      const pw = d.password_hashed ? "(Passwort gehasht)" : e.password;
      return [`${e.username || "–"} / ${pw ?? ""}`, ok ? " " : null, ok];
    }
    case "command": return d.input || "";
    case "request": return d.forward_to ? `Weiterleitung nach ${d.forward_to}` : `${d.method || ""} ${d.path || ""}`;
    case "download": return `${d.upload ? "Upload " + (d.filename || "") : d.url || ""}${d.failed ? " (fehlgeschlagen)" : ""}`;
    case "client_version": return d.version || "";
    case "payload": return d.text || "";
    case "tls": return d.sni ? `SNI ${d.sni}` : "TLS";
    case "fingerprint": return d.hassh ? `HASSH ${d.hassh}` : "";
    case "connect": return d.mode ? `Modus ${MODE_NAME[d.mode] || d.mode}` : "";
    case "disconnect": return [`Dauer ${fmtDur(e.duration_ms)}`, e.tarpit ? [" ", h("span", { class: "badge tarpit" }, `festgehalten ${fmtDur(e.tarpit_ms)}`)] : null];
  }
  return "";
}

function eventRow(e, { fresh = false, showIP = true } = {}) {
  const det = h("td", { class: "det" }, describe(e));
  const tr = h("tr", { class: "click" + (fresh ? " new" : ""), title: "Klicken für Details" },
    h("td", { class: "num" }, fmtTime(e.ts)),
    h("td", null, svcBadge(e.service, e.dst_port)),
    h("td", null, TYPE_NAME[e.type] || e.type),
    showIP ? h("td", null, ipLink(e.src_ip), " ", cc(e.country, e.country_name)) : null,
    det);
  let open = false;
  tr.addEventListener("click", (ev) => {
    if (ev.target.closest("a")) return;
    open = !open;
    tr.classList.toggle("expanded", open);
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

async function viewDashboard(el, ctx) {
  header("Dashboard", { range: true });
  const r = state.range;
  const q = (p) => api(p + (p.includes("?") ? "&" : "?") + "range=" + r);
  const [sum, tl, mp, countries, ports, ips, asns, creds, cmds, recent, sys] = await Promise.all([
    q("stats/summary"), q("stats/timeline"), q("stats/map"),
    q("stats/top?field=country"), q("stats/top?field=port"), q("stats/top?field=ip"), q("stats/top?field=asn"),
    q("stats/top?field=cred"), q("stats/top?field=command"), api("events?limit=12&hide_noise=1"),
    api("system").catch(() => null),
  ]);
  const map = worldMap(mp);
  const recentBody = h("tbody", null, recent.map((e) => eventRow(e)));
  const connTile = tile("Verbindungen", fmtNum(sum.connect));
  mount(el,
    h("div", { class: "stack" },
      warningsBox(sys && sys.warnings, true),
      h("div", { class: "grid kpi" },
        connTile,
        tile("Angreifer-IPs", fmtNum(sum.unique_ips)),
        tile("Länder", fmtNum(sum.countries)),
        tile("Login-Versuche", fmtNum(sum.login)),
        tile("Befehle", fmtNum(sum.command)),
        tile("Downloads", fmtNum(sum.download)),
        tile("Tarpit-Zeit", fmtDur(sum.tarpit_ms), "so lange hingen Angreifer fest"),
        tile("Gerade festgehalten", fmtNum(sum.active_tarpits), "offene Tarpit-Verbindungen")),
      card("Herkunft der Angriffe", map.el,
        h("div", { class: "legend" }, h("span", null, h("i", { class: "swatch", style: { background: "var(--accent)" } }), "Punktgröße = Verbindungen"),
          h("span", null, h("i", { class: "swatch", style: { background: "var(--live)" } }), "neuer Angriff (live)"))),
      card("Verbindungen nach Dienst", timeline(tl)),
      h("div", { class: "grid three" },
        card("Länder", toplist(countries, { key: (x) => x.label || x.key, extra: (x) => cc(x.key) })),
        card("Ports", toplist(ports, { key: (x) => `${x.key} · ${svcName(x.label)}` })),
        card("Angreifer-IPs", toplist(ips, { link: (x) => "#/attacker/" + encodeURIComponent(x.key), extra: (x) => cc(x.label) })),
        card("Netzbetreiber", toplist(asns, { key: (x) => `AS${x.key} ${x.label}` })),
        card("Zugangsdaten", toplist(creds)),
        card("Befehle", toplist(cmds))),
      card("Letzte Aktivität", h("div", { class: "tablewrap" }, h("table", null,
        h("thead", null, h("tr", null, ["Zeit", "Dienst", "Typ", "Quelle", "Details"].map((t) => h("th", null, t)))), recentBody))),
      h("p", null, h("a", { href: "#/feed" }, "Alle Ereignisse im Live-Feed"))));

  let conns = Number(sum.connect) || 0;
  ctx.live((e) => {
    if (e.type === "connect") {
      map.pulse(e.lat, e.lon);
      conns++;
      connTile.querySelector(".value").textContent = fmtNum(conns);
    }
    if (!isNoise(e)) {
      recentBody.prepend(eventRow(e, { fresh: true }));
      while (recentBody.children.length > 12) recentBody.lastChild.remove();
    }
  });
  ctx.every(60000, () => { if (!document.hidden && location.hash.replace("#", "").replace("/", "") === "") route(); });
}

// ---------- Live-Feed ----------

async function viewFeed(el, ctx) {
  const f = { service: "", type: "", q: "", hideNoise: store("hideNoise") !== "0", paused: false };
  const body = h("tbody");
  const info = h("span", { class: "muted" });
  const more = h("button", { class: "btn", onclick: () => load(true) }, "Ältere laden");
  const pauseBtn = h("button", { class: "btn", onclick: () => { f.paused = !f.paused; pauseBtn.textContent = f.paused ? "Fortsetzen" : "Pausieren"; } }, "Pausieren");
  let lastId = 0;

  const params = (before) => {
    const p = new URLSearchParams({ limit: "100" });
    if (f.service) p.set("service", f.service);
    if (f.type) p.set("type", f.type);
    if (f.q) p.set("q", f.q);
    if (f.hideNoise) p.set("hide_noise", "1");
    if (before) p.set("before", String(lastId));
    return p.toString();
  };
  async function load(older) {
    const rows = await api("events?" + params(older));
    if (!older) body.replaceChildren();
    rows.forEach((e) => body.append(eventRow(e)));
    if (rows.length) lastId = rows[rows.length - 1].id;
    more.hidden = rows.length < 100;
    info.textContent = `${fmtNum(body.children.length)} Ereignisse angezeigt`;
  }
  const matches = (e) => (!f.service || e.service === f.service) && (!f.type || e.type === f.type) && !(f.hideNoise && isNoise(e))
    && (!f.q || JSON.stringify(e).toLowerCase().includes(f.q.toLowerCase()));

  const sel = (opts, key, label) => h("select", { "aria-label": label, onchange: (e) => { f[key] = e.target.value; load(); } },
    h("option", { value: "" }, label), opts.map(([v, l]) => h("option", { value: v }, l)));
  let qTimer;
  // Export mit den aktuellen Filtern (Download über den angemeldeten Browser)
  const exRange = h("select", { "aria-label": "Zeitraum für den Export" },
    [["24h", "24 Std"], ["7d", "7 Tage"], ["30d", "30 Tage"], ["90d", "90 Tage"]].map(([v, l]) => h("option", { value: v, selected: v === "7d" }, l)));
  const download = (path) => { const a = h("a", { href: path, download: "" }); document.body.append(a); a.click(); a.remove(); };
  const exportBox = h("div", { class: "filters" },
    h("span", { class: "muted" }, "Export:"), exRange,
    h("button", { class: "btn small", onclick: () => download(`api/export/events?${params()}&format=csv&range=${exRange.value}`) }, "CSV"),
    h("button", { class: "btn small", onclick: () => download(`api/export/events?${params()}&format=json&range=${exRange.value}`) }, "JSON"),
    h("button", { class: "btn small", title: "Öffentliche Angreifer-IPs, eine pro Zeile (z. B. für Firewall-Regeln)", onclick: () => download(`api/export/blocklist?range=${exRange.value}`) }, "Blockliste"));
  header("Live-Feed", { extra: pauseBtn });
  mount(el, h("div", { class: "stack" },
    exportBox,
    h("div", { class: "filters" },
      sel(SERVICES.map((v) => [v, svcName(v)]), "service", "Alle Dienste"),
      sel(Object.entries(TYPE_NAME), "type", "Alle Typen"),
      h("input", { type: "search", placeholder: "Suche: IP, Passwort, Befehl …", oninput: (e) => { clearTimeout(qTimer); qTimer = setTimeout(() => { f.q = e.target.value.trim(); load(); }, 350); } }),
      h("label", { class: "inline" }, h("input", { type: "checkbox", checked: f.hideNoise, onchange: (e) => { f.hideNoise = e.target.checked; store("hideNoise", f.hideNoise ? "1" : "0"); load(); } }), "Verbindungsauf- und -abbau ausblenden"),
      info),
    card(null, h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Zeit", "Dienst", "Typ", "Quelle", "Details"].map((t) => h("th", null, t)))), body))),
    more));
  await load();
  ctx.live((e) => {
    if (f.paused || !matches(e)) return;
    body.prepend(eventRow(e, { fresh: true }));
    while (body.children.length > 1000) body.lastChild.remove();
    info.textContent = `${fmtNum(body.children.length)} Ereignisse angezeigt`;
  });
}

// ---------- Sitzungen ----------

async function viewSessions(el) {
  header("Sitzungen", { range: true });
  const rows = await api("sessions?range=" + state.range);
  const yes = (n, cls = "") => (n ? h("span", { class: "badge " + cls }, fmtNum(n)) : h("span", { class: "muted" }, "–"));
  mount(el, h("div", { class: "stack" },
    h("p", { class: "sub" }, "Verbindungen mit Login-Versuchen, Befehlen oder Downloads. Klick öffnet den Ablauf."),
    card(null, rows.length ? h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Start", "Dienst", "Quelle", "Dauer", "Logins", "Befehle", "Downloads", "Status"].map((t) => h("th", null, t)))),
      h("tbody", null, rows.map((r) => h("tr", { class: "click", onclick: (e) => { if (!e.target.closest("a")) location.hash = "#/session/" + encodeURIComponent(r.session); } },
        h("td", { class: "num" }, fmtDateTime(r.start)),
        h("td", null, svcBadge(r.service, r.dst_port)),
        h("td", null, ipLink(r.src_ip), " ", cc(r.country)),
        h("td", { class: "num" }, fmtDur(r.last - r.start)),
        h("td", null, yes(r.logins)), h("td", null, yes(r.commands)), h("td", null, yes(r.downloads)),
        h("td", null, r.success ? h("span", { class: "badge ok" }, "Login erfolgreich") : null, r.tarpit ? h("span", { class: "badge tarpit" }, "festgehalten") : null))))))
      : h("div", { class: "empty" }, "Noch keine Sitzungen mit Logins oder Befehlen in diesem Zeitraum."))));
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
  mount(el, h("div", { class: "stack" },
    h("div", { class: "grid kpi" },
      tile("Quelle", h("span", null, ipLink(f.src_ip)), [f.city, f.country_name].filter(Boolean).join(", ")),
      tile("Dienst", svcName(f.service), "Port " + f.dst_port),
      tile("Beginn", fmtDateTime(start)), tile("Dauer", fmtDur(end - start))),
    card("Ablauf", h("div", { class: "term" }, evs.map(line)))));
}

// ---------- Angreifer ----------

async function viewAttacker(el, ctx, ip) {
  header("Angreifer " + ip);
  const d = await api("attackers/" + encodeURIComponent(ip));
  const i = d.info;
  mount(el, h("div", { class: "stack" },
    h("div", { class: "grid kpi" },
      tile("Herkunft", i.country_name || i.country || "unbekannt", i.city || null),
      tile("Netzbetreiber", i.asn ? "AS" + i.asn : "–", i.as_org || null),
      tile("Erstmals gesehen", fmtDateTime(i.first_seen)), tile("Zuletzt gesehen", fmtDateTime(i.last_seen), relTime(i.last_seen)),
      tile("Ereignisse", fmtNum(i.events)), tile("Login-Versuche", fmtNum(i.logins)),
      tile("Befehle", fmtNum(i.commands)), tile("Tarpit-Zeit", fmtDur(i.tarpit_ms))),
    h("div", { class: "grid two" },
      card("Angegriffene Ports", toplist(d.ports.map((p) => ({ key: `${p.dst_port} · ${svcName(p.service)}`, n: p.n })))),
      card("Benutzte Zugangsdaten", toplist(d.creds.map((c) => ({ key: `${c.username} / ${c.password}`, n: c.n }))))),
    card("Ereignisse (neueste 300)", evTable(d.events, { showIP: false }))));
}

// ---------- Zugangsdaten ----------

async function viewCreds(el) {
  header("Zugangsdaten und Muster", { range: true });
  const q = (f, n = 25) => api(`stats/top?field=${f}&limit=${n}&range=${state.range}`);
  const [users, pws, combos, cmds, paths, uas, clients] = await Promise.all([
    q("username"), q("password"), q("cred"), q("command"), q("path"), q("useragent", 15), q("client", 15)]);
  mount(el, h("div", { class: "stack" },
    h("div", { class: "grid three" },
      card("Benutzernamen", toplist(users)), card("Passwörter", toplist(pws)), card("Kombinationen", toplist(combos))),
    h("div", { class: "grid two" },
      card("Befehle", toplist(cmds)),
      card("HTTP-Pfade", toplist(paths, { extra: (x) => h("span", { class: "muted" }, svcName(x.label)) }))),
    h("div", { class: "grid two" },
      card("User-Agents", toplist(uas)),
      card("SSH- und Client-Versionen", toplist(clients)))));
}

// ---------- Tarpit ----------

async function viewTarpit(el, ctx) {
  header("Tarpit", { range: true });
  const d = await api("tarpit?range=" + state.range);
  const active = [];
  for (const s of d.sensors) for (const l of s.listeners || []) if (l.mode !== "emulate") active.push({ ...l, sensor: s.sensor });
  mount(el, h("div", { class: "stack" },
    h("p", { class: "sub" }, "Im Tarpit-Modus bekommen Angreifer extrem langsam endlose Daten. Jede Sekunde hier ist Zeit, in der ihr Scanner nichts anderes angreift."),
    h("div", { class: "grid kpi" },
      tile("Verschwendete Angreiferzeit", fmtDur(d.total_ms)),
      tile("Festgehaltene Verbindungen", fmtNum(d.connections), "beendet im Zeitraum"),
      tile("Gerade festgehalten", fmtNum(d.active))),
    card("Ports mit Tarpit oder Hybrid (jetzt)", active.length ? h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Sensor", "Port", "Dienst", "Modus", "Gerade festgehalten", "Offen", "Verbindungen seit Start"].map((t) => h("th", null, t)))),
      h("tbody", null, active.map((l) => h("tr", null, h("td", null, l.sensor), h("td", { class: "num" }, l.port), h("td", null, svcName(l.service)),
        h("td", null, MODE_NAME[l.mode] || l.mode), h("td", { class: "num" }, fmtNum(l.tarpitting)), h("td", { class: "num" }, fmtNum(l.active)), h("td", { class: "num" }, fmtNum(l.total)))))))
      : h("div", { class: "empty" }, "Kein Port im Tarpit- oder Hybrid-Modus. Umschalten unter Einstellungen.")),
    h("div", { class: "grid two" },
      card("Am längsten festgehalten", d.longest.length ? h("div", { class: "tablewrap" }, h("table", null,
        h("thead", null, h("tr", null, ["Ende", "Quelle", "Dienst", "Dauer"].map((t) => h("th", null, t)))),
        h("tbody", null, d.longest.map((r) => h("tr", null, h("td", { class: "num" }, fmtTime(r.ts)), h("td", null, ipLink(r.src_ip), " ", cc(r.country)),
          h("td", null, svcBadge(r.service, r.dst_port)), h("td", { class: "num" }, fmtDur(r.tarpit_ms))))))) : h("div", { class: "empty" }, "Noch keine.")),
      card("Gesamtzeit nach Angreifer", toplist(d.by_ip.map((r) => ({ key: r.src_ip, label: r.country, n: r.tarpit_ms })), {
        link: (x) => "#/attacker/" + encodeURIComponent(x.key), fmt: fmtDur,
      }))),
    card("Gesamtzeit nach Port", toplist(d.by_port.map((r) => ({ key: `${r.dst_port} · ${svcName(r.service)} (${fmtNum(r.n)} Verbindungen)`, n: r.tarpit_ms })), { fmt: fmtDur }))));
  ctx.every(10000, () => { if (!document.hidden && location.hash === "#/tarpit") route(); });
}

// ---------- Einstellungen ----------

async function viewSettings(el) {
  header("Einstellungen");
  const sensor = store("settingsSensor") || "";
  const s = await api("settings?sensor=" + encodeURIComponent(sensor));
  const cfg = s.sensor_config ? structuredClone(s.sensor_config) : null;
  const msg = h("div", { class: "msg", hidden: true });
  const show = (text, ok) => { msg.className = "msg " + (ok ? "ok" : "err"); msg.textContent = text; msg.hidden = false; };

  // Mehrere Sensoren: Konfiguration für alle oder eigene für einen
  const sensorPick = s.sensors && s.sensors.length > 1 ? card("Sensor",
    h("div", { class: "filters" },
      h("select", { "aria-label": "Sensor", onchange: (e) => { store("settingsSensor", e.target.value); route(); } },
        h("option", { value: "", selected: !sensor }, "Alle Sensoren (Standard)"),
        s.sensors.map((n) => h("option", { value: n, selected: n === sensor }, n))),
      sensor ? h("span", { class: "muted" }, s.own_config ? "Dieser Sensor hat eine eigene Konfiguration." : "Dieser Sensor nutzt den Standard; Speichern legt eine eigene an.") : null,
      sensor && s.own_config ? h("button", {
        class: "btn small",
        onclick: async () => { await api("settings", { method: "PUT", body: { sensor, reset_own: true } }); route(); },
      }, "Auf Standard zurücksetzen") : null)) : null;

  if (!cfg) {
    mount(el, card("Noch keine Sensor-Konfiguration",
      h("p", null, "Der Honeypot hat sich noch nicht beim Hive gemeldet. Sobald er läuft (ca. 10 Sekunden nach dem Start), erscheint hier seine Konfiguration."),
      h("button", { class: "btn", onclick: route }, "Neu laden")));
    return;
  }

  const listBody = h("tbody");
  const pubInfo = (port) => {
    const p = s.published[String(port)];
    if (p && p.host) return h("span", { class: "num" }, p.host, h("span", { class: "muted" }, ` (${p.env})`));
    if (p) return h("span", { class: "warn-text" }, `${p.env} fehlt in .env`);
    return h("span", { class: "warn-text" }, "nicht in docker-compose.yml freigegeben");
  };
  function renderListeners() {
    listBody.replaceChildren(...cfg.listeners.map((l, i) => {
      const pub = h("td", null, pubInfo(l.port));
      return h("tr", null,
        h("td", null, h("input", { type: "checkbox", checked: l.enabled, "aria-label": "aktiv", onchange: (e) => { l.enabled = e.target.checked; } })),
        h("td", null, h("select", { "aria-label": "Dienst", onchange: (e) => { l.service = e.target.value; } }, s.services.map((v) => h("option", { value: v, selected: v === l.service }, svcName(v))))),
        h("td", null, h("input", { type: "number", "aria-label": "Port", min: 1, max: 65535, value: l.port, style: { width: "90px" }, onchange: (e) => { l.port = Number(e.target.value); mount(pub, pubInfo(l.port)); } })),
        h("td", null, h("select", { "aria-label": "Modus", onchange: (e) => { l.mode = e.target.value; } }, s.modes.map((v) => h("option", { value: v, selected: v === l.mode }, MODE_NAME[v] || v)))),
        pub,
        h("td", null, h("button", { class: "btn small", onclick: () => { cfg.listeners.splice(i, 1); renderListeners(); } }, "Entfernen")));
    }));
  }
  renderListeners();

  const num = (val, min, max, onset, step) => h("input", { type: "number", min, max, step: step || 1, value: val, style: { width: "110px" }, onchange: (e) => onset(Number(e.target.value)) });
  const row = (label, input, help) => h("div", { class: "form-row" }, h("label", null, label), input, help ? h("div", { class: "help" }, help) : null);
  let retention = s.retention_days;

  async function save() {
    try {
      await api("settings", { method: "PUT", body: { sensor, sensor_config: cfg, retention_days: retention } });
      show("Gespeichert. Der Sensor übernimmt die Änderung innerhalb von 15 Sekunden.", true);
    } catch (e) { show(e.message, false); }
  }

  const pwCur = h("input", { type: "password", autocomplete: "current-password", maxlength: 72 });
  const pwNew = h("input", { type: "password", autocomplete: "new-password", minlength: 10, maxlength: 72 });
  const pwMsg = h("div", { class: "msg", hidden: true });
  async function changePw(e) {
    e.preventDefault();
    try {
      await api("password", { method: "POST", body: { current: pwCur.value, new: pwNew.value } });
      pwMsg.className = "msg ok"; pwMsg.textContent = "Passwort geändert. Alle anderen Sitzungen wurden abgemeldet.";
      pwCur.value = pwNew.value = "";
    } catch (ex) { pwMsg.className = "msg err"; pwMsg.textContent = ex.message; }
    pwMsg.hidden = false;
  }

  mount(el, h("div", { class: "stack" },
    sensorPick,
    card("Ports und Modi",
      h("p", { class: "sub" }, "Welche Dienste der Go-Honeypot anbietet. Die Spalte „Öffentlich“ zeigt den Port auf der NAS laut .env; nur dort freigegebene Ports sind von außen erreichbar."),
      h("div", { class: "tablewrap" }, h("table", null,
        h("thead", null, h("tr", null, ["Aktiv", "Dienst", "Port", "Modus", "Öffentlich (NAS-Port)", ""].map((t) => h("th", null, t)))), listBody)),
      h("p", null, h("button", { class: "btn", onclick: () => { cfg.listeners.push({ service: "raw", port: 5900, mode: "tarpit", enabled: true }); renderListeners(); } }, "Port hinzufügen")),
      h("p", { class: "muted" }, `SSH und Telnet laufen über Cowrie (NAS-Ports ${s.cowrie.ssh || "–"} und ${s.cowrie.telnet || "–"}) und werden in der .env eingestellt.`),
      h("dl", { class: "modes" },
        h("dt", null, "Aufzeichnen"), h("dd", null, "Spielt den Dienst nach, zeichnet Logins, Befehle und Anfragen auf und antwortet normal."),
        h("dt", null, "Tarpit"), h("dd", null, "Hält die Verbindung sofort fest und sendet endlos winzige Datenstücke. Bremst Scanner aus, zeichnet aber kaum etwas auf."),
        h("dt", null, "Hybrid"), h("dd", null, "Zeichnet erst den Login oder die erste Anfrage auf und hält die Verbindung dann fest. Daten und Ausbremsen zugleich."))),
    card("Tarpit",
      row("Intervall (Sekunden)", num(cfg.tarpit.interval_ms / 1000, 0.2, 600, (v) => { cfg.tarpit.interval_ms = Math.round(v * 1000); }, 0.1), "Abstand zwischen zwei Datenstücken. 10 s ist ein guter Wert."),
      row("Max. Verbindungen gesamt", num(cfg.tarpit.max_conns, 1, s.max_tarpit_conns, (v) => { cfg.tarpit.max_conns = v; }),
        `Höchstens ${fmtNum(s.max_tarpit_conns)}. Jede gehaltene Verbindung kostet etwa 10–20 KB RAM; 4096 sind rund 60 MB.`),
      row("Max. Verbindungen pro IP", num(cfg.tarpit.max_per_ip, 1, s.max_tarpit_conns, (v) => { cfg.tarpit.max_per_ip = v; })),
      row("Max. Dauer (Minuten)", num(cfg.tarpit.max_duration_min, 0, 525600, (v) => { cfg.tarpit.max_duration_min = v; }), "Danach wird die Verbindung losgelassen. 1440 = 24 Stunden, 0 = unbegrenzt.")),
    card("Allgemein",
      row("Hostname im Honeypot", h("input", { value: cfg.hostname, maxlength: 64, onchange: (e) => { cfg.hostname = e.target.value.trim(); } }), "Erscheint in Login-Seiten, Docker- und Redis-Antworten."),
      row("Rohdaten aufbewahren (Tage)", num(retention, 1, 3650, (v) => { retention = v; }), "Gilt für alle Sensoren. Danach werden Ereignisse und Angreifer-IPs gelöscht; Statistiken ohne IPs bleiben.")),
    h("div", null, h("button", { class: "btn primary", onclick: save }, sensor ? `Für ${sensor} speichern` : "Speichern"), msg),
    card("Admin-Passwort ändern",
      h("form", { onsubmit: changePw },
        row("Aktuelles Passwort", pwCur), row("Neues Passwort", pwNew, "10 bis 72 Zeichen. Andere angemeldete Geräte werden abgemeldet."),
        h("button", { class: "btn", type: "submit" }, "Passwort ändern"), pwMsg))));
}

// ---------- System ----------

async function viewSystem(el, ctx) {
  header("System");
  const d = await api("system");
  const hv = d.hive;
  const kv = (rows) => h("table", null, h("tbody", null, rows.filter(Boolean).map(([k, v]) => h("tr", null, h("th", null, k), h("td", null, v)))));
  const sensorOk = (s) => Date.now() - toMs(s.seen) < 60000;
  const validDate = (t) => toMs(t) > 0 && new Date(t).getFullYear() > 2000;
  const egressBadge = (e) => (e === "gesperrt" ? h("span", { class: "badge ok" }, "gesperrt")
    : e === "offen" ? h("span", { class: "badge err" }, "offen – Netzsperre fehlt") : h("span", { class: "badge" }, e || "unbekannt"));
  const vols = d.cowrie.volumes || {};
  mount(el, h("div", { class: "stack" },
    warningsBox(d.warnings, false) || h("div", { class: "msg ok" }, "Keine Warnungen."),
    h("div", { class: "grid three" },
      card("Hive", kv([
        ["Version", hv.version], ["Läuft seit", fmtDur(hv.uptime_s * 1000)], ["Arbeitsspeicher", fmtBytes(hv.mem_bytes)],
        ["Datenbank", `${fmtBytes(hv.db_used_bytes)} belegt, Grenze ${fmtBytes(hv.max_db_bytes)}`],
        ["Freier Speicher", hv.disk_free >= 0 ? fmtBytes(hv.disk_free) : "–"],
        ["Gespeicherte Ereignisse", fmtNum(hv.events_stored)], ["Bekannte Angreifer-IPs", fmtNum(hv.attackers)],
        ["Seit Start geschrieben", fmtNum(hv.written)], ["Duplikate verworfen", fmtNum(hv.duplicates)],
        ["Nicht gespeichert", hv.dropped ? h("span", { class: "badge err" }, fmtNum(hv.dropped)) : "0"],
        ["Warteschlange", fmtNum(hv.queue)], ["Aufbewahrung", hv.retention_days + " Tage"],
        ["Letztes Aufräumen", hv.retention && validDate(hv.retention.last_run) ? relTime(hv.retention.last_run) : "noch nicht"]])),
      card("GeoIP", kv([["Status", d.geoip.status], ["Stand", validDate(d.geoip.updated) ? fmtDateTime(d.geoip.updated) : "–"],
        ["Quelle", h("a", { href: "https://db-ip.com", target: "_blank", rel: "noopener noreferrer" }, "IP-Geodaten von DB-IP.com (CC BY 4.0)")]])),
      card("Cowrie (SSH/Telnet)", kv(d.cowrie.enabled ? [
        ["Log-Datei", d.cowrie.found ? h("span", { class: "badge ok" }, "gefunden") : h("span", { class: "badge err" }, "fehlt")],
        ["Letztes Ereignis", relTime(d.cowrie.last_event)],
        vols.log !== undefined ? ["Logs", fmtBytes(vols.log)] : null,
        vols.lib !== undefined ? ["Downloads und Mitschnitte", fmtBytes(vols.lib)] : null] : [["Status", "nicht eingerichtet"]]))),
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
      : card("Sensoren", h("div", { class: "empty" }, "Noch kein Sensor hat sich gemeldet."))));
  ctx.every(15000, () => { if (!document.hidden && location.hash === "#/system" && ctx.current()) route(); });
}

boot();
