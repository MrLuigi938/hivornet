// Einstellungen: fünf Unterseiten (#/settings/<bereich>), jede mit Bereichen, die genau
// das speichern, was in ihnen steht. Knopf und Stand sitzen in der Fußzeile des Bereichs;
// ungespeicherte Änderungen markieren den Bereich, und beim Verlassen der Seite fragt die UI nach.
//
// Endpunkte: /api/settings (Sensor-Konfiguration, Aufbewahrung, erlaubte Hostnamen),
// /api/extras (Zusatzfunktionen; jeder Bereich schickt nur seinen Teil, der Rest bleibt
// wie zuletzt gespeichert), /api/feed, /api/cowrie/auth, /api/users, /api/sensor-tokens,
// /api/password, /api/backup/*.
//
// Wie überall: nur h() und Textknoten, nie HTML aus Zeichenketten.
import { h, mount, api, fmtNum, fmtBytes, fmtDateTime, relTime, store } from "./dom.js";
import { svcName } from "./charts.js";
import { state, header, card, route, MODE_NAME } from "./app.js";
import { forgetHome } from "./extra.js";
import { aiStatusReset } from "./ai.js";

const TABS = [
  ["honeypot", "Honeypot", "Welche Dienste der Honeypot anbietet, wie er sich ausweist und wie er Angreifer festhält."],
  ["auswertung", "Auswertung und KI", "Sprachmodelle für Berichte und Antworten sowie Nachschlagen bei Dritten."],
  ["weitergabe", "Weitergabe und Meldungen", "Benachrichtigungen, Meldungen an AbuseIPDB, URLhaus, MalwareBazaar und DShield sowie die Blockliste für die eigene Firewall."],
  ["zugang", "Zugang und Sicherheit", "Konten, weitere Sensoren, eigene Netze und der Zugriff über einen Reverse-Proxy."],
  ["daten", "Daten und Wartung", "Wie lange Rohdaten bleiben und die verschlüsselte Sicherung."],
];
const ADMIN_ONLY = new Set(["auswertung", "weitergabe"]); // brauchen /api/extras (nur Admin)

// Bereiche mit ungespeicherten Änderungen (für die Rückfrage beim Verlassen)
const dirtyCards = new Set();

const row = (label, input, help) => h("div", { class: "form-row" }, h("label", null, label), input, help ? h("div", { class: "help" }, help) : null);
const isAdmin = () => state.user && state.user.role === "admin";

// section: Bereich mit eigenem Speichern. save() speichert und liefert optional einen
// Erfolgstext; wirft bei Fehlern. Ohne save (oder für die Leserolle) gibt es keinen Knopf.
// Jede Eingabe im Bereich markiert ihn als geändert; Aktionen ohne Eingabefeld rufen markDirty().
function section(title, { intro, save, saveLabel = "Speichern", id } = {}, ...kids) {
  const canSave = !!save && isAdmin();
  const badge = h("span", { class: "dirty-badge", hidden: true }, "Nicht gespeichert");
  const status = h("span", { class: "save-status", role: "status" });
  const btn = canSave ? h("button", { class: "btn primary", disabled: true, onclick: () => doSave() }, saveLabel) : null;
  const el = h("section", { class: "card setting", id },
    h("div", { class: "head" }, h("h2", null, title), h("div", { class: "grow" }), badge),
    intro ? h("p", { class: "sub" }, intro) : null,
    ...kids,
    canSave ? h("div", { class: "card-foot" }, status, btn) : null);
  const sec = {
    el,
    isDirty: () => dirtyCards.has(sec),
    markDirty() {
      if (!canSave) return;
      dirtyCards.add(sec);
      el.classList.add("is-dirty");
      badge.hidden = false;
      btn.disabled = false;
      status.className = "save-status";
      status.textContent = "";
    },
    markClean() {
      dirtyCards.delete(sec);
      el.classList.remove("is-dirty");
      badge.hidden = true;
      if (btn) btn.disabled = true;
    },
    say(text, cls) { status.className = "save-status " + (cls || ""); status.textContent = text; },
    title,
  };
  async function doSave() {
    btn.disabled = true;
    sec.say("Speichere …");
    try {
      const text = await save();
      sec.markClean();
      sec.say(text || "Gespeichert.", "ok");
    } catch (e) {
      btn.disabled = false;
      sec.say(e.message, "err");
    }
  }
  if (canSave) {
    const onEdit = (e) => { if (!e.target.closest("[data-nodirty]")) sec.markDirty(); };
    el.addEventListener("input", onEdit);
    el.addEventListener("change", onEdit);
  }
  return sec;
}

// ---------- Seite ----------

export async function viewSettings(el, ctx, tab) {
  header("Einstellungen");
  dirtyCards.clear();
  const tabs = TABS.filter(([k]) => isAdmin() || !ADMIN_ONLY.has(k));
  if (!tabs.some(([k]) => k === tab)) tab = tabs[0][0];
  const [, , lead] = TABS.find(([k]) => k === tab);

  // Rückfrage beim Verlassen mit ungespeicherten Änderungen (Unterseite, andere Seite, Neuladen)
  const names = () => [...dirtyCards].map((s) => "„" + s.title + "“").join(", ");
  state.leaveGuard = () => !dirtyCards.size || confirm(`Ungespeicherte Änderungen in ${names()}. Seite trotzdem verlassen?`);
  const beforeUnload = (e) => { if (dirtyCards.size) { e.preventDefault(); e.returnValue = ""; } };
  window.addEventListener("beforeunload", beforeUnload);
  ctx.onCleanup(() => { state.leaveGuard = null; window.removeEventListener("beforeunload", beforeUnload); dirtyCards.clear(); });

  const nav = h("nav", { class: "subnav", "aria-label": "Bereiche der Einstellungen" },
    tabs.map(([k, label]) => h("a", { href: "#/settings/" + k, class: k === tab ? "on" : null, "aria-current": k === tab ? "page" : null }, label)));
  const body = h("div", { class: "stack" }, h("p", { class: "muted" }, "Lade …"));
  mount(el, h("div", { class: "settings" }, nav,
    h("p", { class: "lead" }, lead),
    isAdmin() ? null : h("div", { class: "msg" }, "Nur Lesezugriff: Ändern kann nur ein Admin. Dein eigenes Passwort kannst du unter „Zugang und Sicherheit“ ändern."),
    body));
  nav.querySelector("a.on")?.scrollIntoView({ block: "nearest", inline: "center" }); // schmaler Bildschirm: aktive Unterseite sichtbar
  const build = { honeypot: tabHoneypot, auswertung: tabAuswertung, weitergabe: tabWeitergabe, zugang: tabZugang, daten: tabDaten }[tab];
  mount(body, await build());
}

// ---------- Honeypot ----------

async function tabHoneypot() {
  const sensor = store("settingsSensor") || "";
  const s = await api("settings?sensor=" + encodeURIComponent(sensor));
  const out = [];
  if (s.sensors && s.sensors.length > 1) out.push(sensorPicker(s, sensor));
  if (!s.sensor_config) {
    out.push(card("Noch keine Sensor-Konfiguration",
      h("p", null, "Der Honeypot hat sich noch nicht beim Hive gemeldet. Sobald er läuft (ca. 10 Sekunden nach dem Start), erscheint hier seine Konfiguration."),
      h("button", { class: "btn", onclick: () => route() }, "Neu laden")));
  } else {
    const saved = structuredClone(s.sensor_config); // Stand auf dem Hive
    const saveCfg = async (part) => {
      await api("settings", { method: "PUT", body: { sensor, sensor_config: { ...structuredClone(saved), ...structuredClone(part) } } });
      Object.assign(saved, structuredClone(part));
      return sensor ? `Für ${sensor} gespeichert. Der Sensor übernimmt es innerhalb von 15 Sekunden.` : "Gespeichert. Der Sensor übernimmt es innerhalb von 15 Sekunden.";
    };
    // Verbindungen je Port (hive/silentports.go): Hinweis auf stille Ports, Folgen eines Profilwechsels
    const act = await api("ports/activity?sensor=" + encodeURIComponent(sensor)).catch(() => null);
    const byPort = new Map(((act && act.ports) || []).map((p) => [p.port, p]));
    const ports = portsCard(s, saved, saveCfg, byPort);
    out.push(ports.el, profileCard(s, saved, saveCfg, ports, byPort).el, tarpitCard(s, saved, saveCfg).el);
  }
  if (isAdmin()) {
    out.push(cowrieAuthCard());
    const ex = await extrasCtx().catch(() => null);
    if (ex) out.push(bruteCard(ex).el, homeCard(ex).el);
  }
  return out;
}

function sensorPicker(s, sensor) {
  return card("Sensor",
    h("div", { class: "filters" },
      h("select", { "aria-label": "Sensor", onchange: (e) => {
        if (state.leaveGuard && !state.leaveGuard()) { e.target.value = sensor; return; }
        dirtyCards.clear();
        store("settingsSensor", e.target.value); route();
      } },
      h("option", { value: "", selected: !sensor }, "Alle Sensoren (Standard)"),
      s.sensors.map((n) => h("option", { value: n, selected: n === sensor }, n))),
      sensor ? h("span", { class: "muted" }, s.own_config ? "Dieser Sensor hat eine eigene Konfiguration." : "Dieser Sensor nutzt den Standard; Speichern legt eine eigene an.") : null,
      sensor && s.own_config && isAdmin() ? h("button", {
        class: "btn small",
        onclick: async () => {
          if (!confirm(`Eigene Konfiguration von ${sensor} löschen? Der Sensor nutzt danach wieder den Standard.`)) return;
          await api("settings", { method: "PUT", body: { sensor, reset_own: true } });
          dirtyCards.clear(); route();
        },
      }, "Auf Standard zurücksetzen") : null),
    h("p", { class: "help" }, "Ports, Geräteprofil und Tarpit gelten für den hier gewählten Sensor."));
}

// Ports und Modi. Wählt man in einer Zeile den Dienst, springt der Port auf dessen Standardport
// (vom Server: default_ports), solange der Port in dieser Zeile nicht von Hand geändert wurde.
function portsCard(s, saved, saveCfg, byPort = new Map()) {
  const defs = s.default_ports || {};
  const reserved = s.reserved_ports || {};
  let ls = [];
  const meta = new WeakMap(); // Zeile -> { auto, note, isNew, portIn, hint }
  const listBody = h("tbody");

  const pubInfo = (port) => {
    if (s.direct_ports) return h("span", { class: "muted" }, "direkt am Gerät");
    const p = s.published[String(port)];
    if (p && p.host) return h("span", null, h("span", { class: "num" }, p.host), h("span", { class: "muted" }, ` (${p.env})`));
    if (p) return h("span", { class: "warn-text" }, `${p.env} fehlt in .env`);
    return h("span", { class: "warn-text" }, "nicht in docker-compose.yml freigegeben");
  };
  const hintFor = (l) => {
    const m = meta.get(l);
    if (!l.service) return h("span", { class: "muted" }, "Dienst wählen; der Port wird dann vorgeschlagen.");
    if (m.note) return h("span", { class: "warn-text" }, m.note);
    if (!l.port) return h("span", { class: "warn-text" }, "Port fehlt.");
    if (reserved[l.port]) return h("span", { class: "warn-text" }, `Port ${l.port} ist reserviert (${reserved[l.port]}).`);
    const other = ls.find((o) => o !== l && o.port === l.port);
    if (other) return h("span", { class: "warn-text" }, `Port ${l.port} ist schon belegt (${svcName(other.service) || other.service}).`);
    const a = l.enabled && byPort.get(l.port);
    if (a && a.silent) return h("div", null, h("span", { class: "warn-text" }, a.text), " ", pubInfo(l.port));
    if (a && a.active_since) return h("div", null, pubInfo(l.port), h("div", { class: "muted" }, `7 Tage: ${fmtNum(a.conns_7d)} Verbindung${a.conns_7d === 1 ? "" : "en"}`));
    return pubInfo(l.port);
  };
  const refreshHints = () => { for (const l of ls) mount(meta.get(l).hint, hintFor(l)); };

  function pickService(l, v) {
    const m = meta.get(l);
    l.service = v;
    // SSH-Tarpit hält nur fest: in neuen Zeilen den Modus mitnehmen, solange er nicht von Hand gewählt wurde
    if (m.isNew && !m.modeTouched) { l.mode = v === "ssh-tarpit" ? "tarpit" : "emulate"; m.modeSel.value = l.mode; }
    const def = defs[v];
    m.note = "";
    if (m.auto && def) {
      const taken = ls.find((o) => o !== l && o.port === def);
      if (taken) m.note = `Standardport ${def} ist schon belegt (${svcName(taken.service) || taken.service}). Bitte einen anderen Port eintragen.`;
      else if (reserved[def]) m.note = `Standardport ${def} ist reserviert (${reserved[def]}). Bitte einen anderen Port eintragen.`;
      else { l.port = def; m.portIn.value = def; }
    }
    refreshHints();
  }

  function renderRows() {
    listBody.replaceChildren(...ls.map((l, i) => {
      const m = meta.get(l);
      m.hint = h("td", { class: "hint", "data-label": "Hinweis" });
      m.portIn = h("input", { type: "number", "aria-label": "Port", min: 1, max: 65535, value: l.port || "", placeholder: "Port", class: "port-in",
        oninput: (e) => { m.auto = false; m.note = ""; l.port = Number(e.target.value) || 0; refreshHints(); } });
      m.modeSel = h("select", { "aria-label": "Modus", onchange: (e) => { l.mode = e.target.value; m.modeTouched = true; } },
        s.modes.map((v) => h("option", { value: v, selected: v === l.mode }, MODE_NAME[v] || v)));
      return h("tr", null,
        h("td", { class: "on", "data-label": "Aktiv" }, h("input", { type: "checkbox", checked: l.enabled, "aria-label": "aktiv", onchange: (e) => { l.enabled = e.target.checked; } })),
        h("td", { class: "svc", "data-label": "Dienst" }, h("select", { "aria-label": "Dienst", onchange: (e) => pickService(l, e.target.value) },
          l.service ? null : h("option", { value: "", selected: true, disabled: true }, "Dienst wählen …"),
          s.services.map((v) => h("option", { value: v, selected: v === l.service }, svcName(v))))),
        h("td", { class: "port", "data-label": "Port" }, m.portIn),
        h("td", { class: "mode", "data-label": "Modus" }, m.modeSel),
        m.hint,
        h("td", { class: "act" }, h("button", { class: "btn small", onclick: () => { ls.splice(i, 1); renderRows(); sec.markDirty(); } }, "Entfernen")));
    }));
    refreshHints();
  }
  function reset() {
    ls = structuredClone(saved.listeners);
    for (const l of ls) meta.set(l, { auto: defs[l.service] === l.port, note: "", isNew: false });
    renderRows();
    sec.markClean();
  }
  function add() {
    const l = { service: "", port: 0, mode: "emulate", enabled: true };
    meta.set(l, { auto: true, note: "", isNew: true });
    ls.push(l);
    renderRows();
    sec.markDirty();
    meta.get(l).hint.closest("tr").querySelector("select").focus();
  }

  const cowrieNote = s.direct_ports
    ? "SSH (22) und Telnet (23) gehören Cowrie und sind hier gesperrt; der Go-Honeypot nimmt dafür 2222 (SSH-Tarpit) und 2323 (Telnet)."
    : `SSH und Telnet laufen über Cowrie (NAS-Ports ${s.cowrie.ssh || "–"} und ${s.cowrie.telnet || "–"}, eingestellt in der .env). Der Go-Honeypot nimmt 2222 (SSH-Tarpit) und 2323 (Telnet).`;
  const sec = section("Ports und Modi", {
    intro: s.direct_ports ? "Welche Dienste der Go-Honeypot anbietet. Er lauscht direkt auf diesen Ports des Geräts." :
      "Welche Dienste der Go-Honeypot anbietet. Die Spalte „Hinweis“ zeigt den Port auf der NAS laut .env; nur dort freigegebene Ports sind von außen erreichbar.",
    saveLabel: "Ports speichern",
    save: async () => {
      const bad = ls.findIndex((l) => !l.service || !l.port);
      if (bad >= 0) throw new Error(`Zeile ${bad + 1}: bitte Dienst und Port angeben.`);
      const r = await saveCfg({ listeners: ls.map(({ service, port, mode, enabled }) => ({ service, port, mode, enabled })) });
      for (const l of ls) Object.assign(meta.get(l), { auto: defs[l.service] === l.port, isNew: false, note: "" });
      return r;
    },
  },
  h("div", { class: "tablewrap" }, h("table", { class: "ports" },
    h("thead", null, h("tr", null, ["Aktiv", "Dienst", "Port", "Modus", "Hinweis", ""].map((t) => h("th", null, t)))), listBody)),
  h("div", { class: "btnrow" }, h("button", { class: "btn", onclick: add }, "Port hinzufügen")),
  silentBox(s, saved, byPort, (port) => {
    const l = ls.find((x) => x.port === port);
    if (!l) return;
    l.enabled = false;
    renderRows();
    sec.markDirty();
  }),
  h("p", { class: "muted" }, cowrieNote),
  h("details", null, h("summary", null, "Was die Modi bedeuten"),
    h("dl", { class: "modes" },
      h("dt", null, "Aufzeichnen"), h("dd", null, "Spielt den Dienst nach, zeichnet Logins, Befehle und Anfragen auf und antwortet normal."),
      h("dt", null, "Tarpit"), h("dd", null, "Hält die Verbindung sofort fest und sendet endlos winzige Datenstücke. Bremst Scanner aus, zeichnet aber kaum etwas auf."),
      h("dt", null, "Hybrid"), h("dd", null, "Zeichnet erst den Login oder die erste Anfrage auf und hält die Verbindung dann fest. Daten und Ausbremsen zugleich."))));
  sec.reset = reset;
  reset();
  return sec;
}

// Stille Ports: Kasten über den Ports mit Erklärung, Prüfhinweisen und „Abschalten“.
// Geprüft wird nichts aktiv; Shodan (System) und ein Portprüfer im Browser nur auf Knopfdruck.
function silentBox(s, saved, byPort, switchOff) {
  const silent = saved.listeners.filter((l) => l.enabled && byPort.get(l.port)?.silent);
  if (!silent.length) return null;
  const box = h("div", { class: "msg warn silent-ports" },
    h("b", null, silent.length === 1 ? "Ein Port bekommt keine Verbindungen" : `${silent.length} Ports bekommen keine Verbindungen`),
    h("ul", null, silent.map((l) => h("li", null, byPort.get(l.port).text, " ",
      isAdmin() ? h("button", { type: "button", class: "btn small", onclick: (e) => { e.target.disabled = true; e.target.textContent = "Abgeschaltet (noch speichern)"; switchOff(l.port); } }, "Dienst abschalten") : null))),
    h("details", null, h("summary", null, "Woran das liegen kann und wie du es prüfst"),
      h("ul", null,
        h("li", null, "Viele Internetanbieter (etwa Vodafone) sperren an Privatanschlüssen eingehend Port 25 (Mail) und 445 (Windows-Freigaben). Dann kommt dort nie etwas an; Abschalten spart nur Ressourcen."),
        h("li", null, s.direct_ports ? "Im Router muss der Port auf dieses Gerät weitergeleitet sein (Portfreigabe)."
          : "Im Docker-Betrieb muss der Port in der .env freigegeben und im Router auf denselben NAS-Port weitergeleitet sein (Spalte „Hinweis“)."),
        h("li", null, "Ob der Port von außen offen ist, zeigt „Wie Shodan dich sieht“ unter System (Abfrage nur auf Knopfdruck) oder ein Online-Portprüfer, den du selbst im Browser aufrufst. Der Hive prüft nichts von außen."))));
  return box;
}

// Geräteprofile wie in honeypot/profile.go: passende Dienste und ein Hostname.
// Banner und Versionen setzt der Honeypot selbst passend zum Profil.
const PROFILES = {
  "": { name: "Bisher (gemischt, wie vor 0.5.3)", desc: "Alle Dienste mit den bisherigen Kennungen, damit sich bestehende Installationen nicht ändern. Von außen wirkt das Gerät widersprüchlich (Windows-RDP, Router-Telnet und Ubuntu-Mailserver zugleich)." },
  "linux-server": { name: "Linux-Server (Ubuntu 22.04)", host: "web01", desc: "Gemieteter Web- und Datenbankserver mit nginx, MySQL, PostgreSQL, Redis, Postfix und Docker.",
    services: ["http", "https", "ssh-tarpit", "ftp", "mysql", "redis", "postgres", "smtp", "dockerapi"] },
  "nas": { name: "Heim-NAS (Debian 11)", host: "nas-backup01", desc: "Heim-NAS wie openmediavault: Weboberfläche, FTP, MariaDB, Redis, Docker, Mail und SNMP.",
    services: ["http", "https", "ftp", "ssh-tarpit", "mysql", "redis", "dockerapi", "smtp", "snmp"] },
  "router": { name: "WLAN-Router (BusyBox, MIPS)", host: "router", desc: "Router mit Hersteller-Firmware (lighttpd, Dropbear, BusyBox), wie ihn IoT-Botnetze über Telnet angreifen.",
    services: ["http", "https", "telnet", "ftp", "ssh-tarpit", "dns", "snmp", "sip"] },
  "ip-camera": { name: "IP-Kamera (BusyBox, ARM)", host: "ipcam-hof", desc: "Billige IP-Kamera mit Boa-Webserver und Telnet-Zugang mit Werkspasswort.",
    services: ["http", "telnet", "ftp", "ssh-tarpit"] },
  "smart-home": { name: "Smart-Home-Zentrale (Raspberry Pi)", host: "raspberrypi", desc: "Raspberry Pi 4 mit Raspberry Pi OS (Debian 12, 64 Bit): MQTT-Broker, Weboberfläche, VNC und Docker.",
    services: ["http", "https", "mqtt", "ssh-tarpit", "vnc", "dockerapi"] },
  "dev-server": { name: "Entwicklungs- und KI-Server (Ubuntu 24.04)", host: "gpu-dev01", desc: "Server mit Docker, Kubernetes, Ollama, Elasticsearch und Datenbanken; beliebtes Ziel für Krypto-Miner.",
    services: ["http", "https", "ssh-tarpit", "dockerapi", "kubernetes", "ollama", "elasticsearch", "postgres", "redis", "mysql"] },
};

// Hostname nach RFC 952/1123 (wie hive/hostname.go): Buchstaben, Ziffern, Bindestrich,
// je Teil höchstens 63 Zeichen, kein Bindestrich am Rand. "" = gültig oder leer.
export function hostnameProblem(v) {
  if (!v) return "";
  if (v.length > 64) return "höchstens 64 Zeichen";
  for (const c of v) {
    if (c === "_") return "Unterstriche sind in Hostnamen nicht erlaubt";
    if (c === " ") return "Leerzeichen sind in Hostnamen nicht erlaubt";
    if (c.charCodeAt(0) > 0x7f) return "Umlaute und andere Sonderzeichen sind nicht erlaubt";
    if (!/[A-Za-z0-9.-]/.test(c)) return `Zeichen „${c}“ ist nicht erlaubt (nur Buchstaben, Ziffern und Bindestrich)`;
  }
  for (const l of v.split(".")) {
    if (!l) return "leerer Namensteil (zwei Punkte hintereinander oder Punkt am Anfang/Ende)";
    if (l.length > 63) return "ein Namensteil darf höchstens 63 Zeichen haben";
    if (l.startsWith("-") || l.endsWith("-")) return "kein Bindestrich am Anfang oder Ende";
  }
  return "";
}

export function suggestHostname(v) {
  v = v.trim().toLowerCase().replace(/ä/g, "ae").replace(/ö/g, "oe").replace(/ü/g, "ue").replace(/ß/g, "ss");
  v = v.replace(/[^a-z0-9.]/g, "-");
  let s = v.split(".").map((p) => p.replace(/-+/g, "-").replace(/^-|-$/g, "").slice(0, 63).replace(/-$/, "")).filter(Boolean).join(".");
  if (s.length > 64) s = s.slice(0, 64).replace(/-+$/, "").replace(/\.+$/, "");
  return s;
}

// Wie viele Verbindungen die Dienste brachten, die ein Profil ausschaltet ("" = unbekannt oder keine).
function offImpact(off, byPort) {
  const parts = off.map((l) => ({ name: svcName(l.service), n: byPort.get(l.port)?.conns_7d || 0 })).filter((x) => x.n > 0);
  if (!parts.length) return "";
  const total = parts.reduce((a, x) => a + x.n, 0);
  const names = [...new Set(parts.map((x) => x.name))];
  const list = names.length > 1 ? names.slice(0, -1).join(", ") + " und " + names.at(-1) : names[0];
  return `${list} brachte${names.length > 1 ? "n" : ""} zuletzt ~${fmtNum(total)} Verbindung${total === 1 ? "" : "en"} pro Woche` +
    (parts.length > 1 ? ` (${parts.map((x) => `${x.name} ${fmtNum(x.n)}`).join(", ")})` : "") + ".";
}

function profileCard(s, saved, saveCfg, ports, byPort = new Map()) {
  const known = s.profiles || Object.keys(PROFILES);
  const keys = Object.keys(PROFILES).filter((k) => known.includes(k));
  const info = h("p", { class: "help" });
  const preview = h("p", { class: "help" });
  const impact = h("p", { class: "warn-text", role: "status" });
  const sel = h("select", { "aria-label": "Profil", onchange: () => { apply.checked = !!PROFILES[sel.value].services; show(); } },
    keys.map((k) => h("option", { value: k, selected: (saved.profile || "") === k }, PROFILES[k].name)));
  const hostHint = h("div", { class: "host-hint", role: "status" });
  const hostIn = h("input", { value: saved.hostname, maxlength: 64, "aria-label": "Hostname", spellcheck: "false", autocomplete: "off", oninput: () => checkHost() });
  // Hinweis beim Tippen, mit Vorschlag zum Übernehmen
  const checkHost = () => {
    const v = hostIn.value.trim(), why = hostnameProblem(v);
    hostIn.setAttribute("aria-invalid", why ? "true" : "false");
    if (!why) { hostHint.replaceChildren(); return; }
    const sug = suggestHostname(v);
    hostHint.replaceChildren(h("div", { class: "msg warn" },
      `So heißt kein echtes Gerät: ${why}. Erlaubt sind Buchstaben, Ziffern und Bindestrich (je Teil höchstens 63 Zeichen, kein Bindestrich am Anfang oder Ende).`,
      sug && !hostnameProblem(sug) ? [" Vorschlag: ", h("b", { class: "num" }, sug), " ",
        h("button", { type: "button", class: "btn small", onclick: () => { hostIn.value = sug; checkHost(); sec.markDirty(); } }, "Übernehmen")] : null));
  };
  // Köder des Web-Honeypots (honeypot/lures.go); eine eigene Liste aus der YAML-Datei bleibt erhalten
  const lureOpts = { "": "Passend zum Profil", all: "Alle", off: "Aus" };
  if (saved.lures && !(saved.lures in lureOpts)) lureOpts[saved.lures] = "Eigene Auswahl: " + saved.lures;
  const lureSel = h("select", { "aria-label": "Köder" },
    Object.keys(lureOpts).map((k) => h("option", { value: k, selected: (saved.lures || "") === k }, lureOpts[k])));
  const apply = h("input", { type: "checkbox", onchange: () => show() });
  const applyRow = h("label", { class: "inline" }, apply, "Passende Dienste einschalten, die übrigen ausschalten, und den Hostnamen vorschlagen");
  const show = () => {
    const p = PROFILES[sel.value];
    info.textContent = p.desc;
    applyRow.hidden = !p.services;
    if (apply.checked && p.host && hostIn.value === saved.hostname) { hostIn.value = p.host; checkHost(); }
    if (!p.services || !apply.checked) { preview.textContent = ""; impact.textContent = ""; return; }
    const on = [], off = [], offL = [];
    for (const l of saved.listeners) {
      const want = p.services.includes(l.service);
      if (want && !l.enabled) on.push(`${svcName(l.service)} ${l.port}`);
      if (!want && l.enabled) { off.push(`${svcName(l.service)} ${l.port}`); offL.push(l); }
    }
    impact.textContent = offImpact(offL, byPort);
    const missing = p.services.filter((v) => !saved.listeners.some((l) => l.service === v)).map(svcName);
    preview.textContent = [on.length ? "Schaltet ein: " + on.join(", ") : "", off.length ? "Schaltet aus: " + off.join(", ") : "",
      missing.length ? "Nicht eingerichtet (unter „Ports und Modi“ hinzufügen): " + missing.join(", ") : ""].filter(Boolean).join(" · ") || "Die Dienste passen schon zum Profil.";
  };
  const sec = section("Geräteprofil", {
    intro: "Damit das Gerät von außen stimmig wirkt: Das Profil bestimmt Banner, Versionen und Kernel aller Dienste des Go-Honeypots. Cowrie (SSH/Telnet) behält seine eigenen Einstellungen.",
    saveLabel: "Profil speichern",
    save: async () => {
      const p = PROFILES[sel.value];
      const part = { profile: sel.value, hostname: hostIn.value.trim(), lures: lureSel.value };
      if (part.hostname !== saved.hostname && hostnameProblem(part.hostname)) {
        const sug = suggestHostname(part.hostname);
        if (!sug || hostnameProblem(sug) || !confirm(`„${part.hostname}“ ist kein gültiger Hostname (${hostnameProblem(part.hostname)}). Stattdessen „${sug}“ speichern?`))
          throw new Error("Hostname ungültig: bitte korrigieren oder den Vorschlag übernehmen.");
        part.hostname = hostIn.value = sug;
        checkHost();
      }
      if (apply.checked && p.services) {
        if (ports.isDirty()) throw new Error("Bitte zuerst „Ports und Modi“ speichern; das Profil schaltet dort Dienste um.");
        const lost = offImpact(saved.listeners.filter((l) => l.enabled && !p.services.includes(l.service)), byPort);
        if (lost && !confirm(`Das Profil schaltet Dienste aus: ${lost} Trotzdem speichern?`)) throw new Error("Nicht gespeichert.");
        part.listeners = saved.listeners.map((l) => ({ ...l, enabled: p.services.includes(l.service) }));
      }
      const r = await saveCfg(part);
      if (part.listeners) ports.reset();
      apply.checked = false;
      show();
      return r;
    },
  },
  row("Profil", sel), info,
  row("Hostname", h("div", null, hostIn, hostHint),
    "Erscheint in Login-Seiten, Bannern, Zertifikaten sowie Docker- und Redis-Antworten und geht mit den Befehlen an den Anbieter des Sprachmodells, falls die KI-Antworten eingeschaltet sind. " +
    "Ein unauffälliger Name wie „web01“ oder „nas-backup01“ wirkt echt; ungültige oder seltsame Namen verraten den Honeypot. Bitte keine echten Personennamen oder Hinweise auf dich verwenden."),
  row("Köder", lureSel, "Glaubwürdige Seiten für oft angegriffene Produkte (FortiGate, Ivanti, Cisco ASA, Hikvision, ONVIF, Tomcat, Jira und Keycloak). Passend zum Profil: Kamera zeigt Hikvision und ONVIF, Server zeigen Tomcat und Java-Anwendungen."),
  applyRow, preview, impact);
  show();
  checkHost();
  return sec;
}

function tarpitCard(s, saved, saveCfg) {
  const t = structuredClone(saved.tarpit);
  const num = (val, min, max, onset, step) => h("input", { type: "number", min, max, step: step || 1, value: val, style: { width: "110px" }, onchange: (e) => onset(Number(e.target.value)) });
  return section("Tarpit", {
    intro: "Gilt für alle Ports im Modus Tarpit oder Hybrid.",
    saveLabel: "Tarpit speichern",
    save: () => saveCfg({ tarpit: t }),
  },
  row("Intervall (Sekunden)", num(t.interval_ms / 1000, 0.2, 600, (v) => { t.interval_ms = Math.round(v * 1000); }, 0.1), "Abstand zwischen zwei Datenstücken. 10 s ist ein guter Wert."),
  row("Max. Verbindungen gesamt", num(t.max_conns, 1, s.max_tarpit_conns, (v) => { t.max_conns = v; }),
    `Höchstens ${fmtNum(s.max_tarpit_conns)}. Jede gehaltene Verbindung kostet etwa 10–20 KB RAM; 4096 sind rund 60 MB.`),
  row("Max. Verbindungen pro IP", num(t.max_per_ip, 1, s.max_tarpit_conns, (v) => { t.max_per_ip = v; })),
  row("Max. Dauer (Minuten)", num(t.max_duration_min, 0, 525600, (v) => { t.max_duration_min = v; }), "Danach wird die Verbindung losgelassen. 1440 = 24 Stunden, 0 = unbegrenzt."));
}

// SSH und Telnet (Cowrie): Anmelderegel. Raspberry Pi: über hivornet-cowrie-config (root)
// angewendet; Docker: nur Anzeige, die Regel steht in der .env.
function cowrieAuthCard() {
  const body = h("div", null, h("p", { class: "muted" }, "Lade …"));
  const box = card("SSH und Telnet (Cowrie): Anmeldung", body);
  box.classList.add("setting");
  const load = async () => {
    let d;
    try { d = await api("cowrie/auth"); } catch (e) { mount(body, h("div", { class: "msg err" }, e.message)); return; }
    if (d.platform === "none") { mount(body, h("p", { class: "muted" }, "Cowrie ist hier nicht eingerichtet.")); return; }
    const cur = d.current || { mode: "random", min: 2, max: 5 };
    const mode = h("select", { "aria-label": "Anmelderegel" },
      h("option", { value: "random", selected: cur.mode === "random" }, "Erst nach mehreren Versuchen (empfohlen)"),
      h("option", { value: "all", selected: cur.mode === "all" }, "Jede Kombination sofort (auffällig)"));
    const min = h("input", { type: "number", min: 1, max: 20, value: cur.min || 2, style: { width: "80px" }, "aria-label": "Mindestens" });
    const max = h("input", { type: "number", min: 1, max: 20, value: cur.max || 5, style: { width: "80px" }, "aria-label": "Höchstens" });
    const range = h("div", { class: "form-row" }, h("label", null, "Versuche je IP"),
      h("div", null, "zwischen ", min, " und ", max, h("div", { class: "help", style: { marginTop: "4px" } },
        "Cowrie wählt je Angreifer-IP zufällig eine Zahl in diesem Bereich. Erst dann klappt eine Anmeldung; die erfolgreiche Kombination gilt für diese IP weiter.")));
    const sync = () => { range.style.display = mode.value === "random" ? "" : "none"; };
    mode.addEventListener("change", sync);
    sync();
    const st = d.status;
    const status = h("span", { class: "save-status", role: "status" });
    const btn = h("button", { class: "btn primary", disabled: true }, "Regel übernehmen");
    const edited = () => { btn.disabled = false; box.classList.add("is-dirty"); status.className = "save-status"; status.textContent = "Nicht übernommen"; };
    for (const x of [mode, min, max]) x.addEventListener("input", edited);
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      status.textContent = "Wird übernommen …";
      try {
        await api("cowrie/auth", { method: "PUT", body: { mode: mode.value, min: Number(min.value), max: Number(max.value) } });
        box.classList.remove("is-dirty");
        status.className = "save-status ok"; status.textContent = "Angefordert; Cowrie startet in wenigen Sekunden neu.";
        setTimeout(load, 6000);
      } catch (e) { btn.disabled = false; status.className = "save-status err"; status.textContent = e.message; }
    });
    mount(body,
      h("p", { class: "sub" }, "Wie leicht Angreifer in die gefälschte Shell kommen. Nimmt Cowrie jede Kombination sofort an, erkennen geübte Bots den Honeypot; ",
        "zu hohe Hürden bedeuten dagegen, dass weniger Angreifer Befehle eingeben."),
      h("p", null, "Aktuell: ", h("b", null, d.current_text || "unbekannt"),
        st ? h("span", { class: "muted" }, ` · zuletzt geändert ${relTime(st.since)}${st.state === "failed" ? " (fehlgeschlagen: " + st.text + ")" : ""}`) : null,
        d.pending ? h("span", { class: "muted" }, " · Änderung wird gerade übernommen …") : null),
      d.can_apply ? [
        h("div", { class: "form-row" }, h("label", null, "Regel"), mode), range,
        h("div", { class: "card-foot" }, status, btn),
      ] : h("div", { class: "msg" }, "Im Docker-Betrieb steht die Regel in der Datei .env: ",
        h("code", null, "COWRIE_AUTH_CLASS=AuthRandom"), " und ", h("code", null, "COWRIE_AUTH_PARAMS=2, 5, 10"),
        " (Mindest- und Höchstzahl der Versuche) bzw. ", h("code", null, "COWRIE_AUTH_CLASS=UserDB"), " für jede Kombination sofort. Danach ",
        h("code", null, "docker compose up -d"), "."));
  };
  load();
  return box;
}

// Dauer-Brute-Force (hive/bruteforce.go): Erkennen, Verdichten und Drossel in der Firewall.
// Raspberry Pi: Die Drossel übernimmt hivornet-cowrie-config (root) beim Speichern; Docker: Aufruf
// von tools/firewall.sh auf dem Host, den die Karte mit den gespeicherten Werten anzeigt.
function bruteCard(ex) {
  const b = ex.x.brute = ex.x.brute || { condense: true, min_logins: 200, min_minutes: 30, max_clients: 3, limit: false, rate: 6, burst: 20, ban_minutes: 15 };
  const state = h("div", null, h("p", { class: "muted" }, "Lade …"));
  const show = async () => {
    let d;
    try { d = await api("brute"); } catch (e) { mount(state, h("div", { class: "msg err" }, e.message)); return; }
    const st = d.status;
    mount(state,
      d.condensed || d.summaries ? h("p", { class: "muted" }, `Seit dem Start verdichtet: ${fmtNum(d.condensed)} Ereignisse in ${fmtNum(d.summaries)} Sammelzeilen.`) : null,
      d.platform === "pi" ? h("p", null, "Drossel in der Firewall: ",
        h("b", null, st ? (st.state === "ok" ? st.text : "fehlgeschlagen: " + st.text) : "noch nie angefordert"),
        st ? h("span", { class: "muted" }, ` · ${relTime(st.since)}`) : null,
        d.pending ? h("span", { class: "muted" }, " · Änderung wird gerade übernommen …") : null) : null,
      d.platform === "docker" ? h("div", { class: "msg" },
        "Im Docker-Betrieb setzt die Firewall auf dem Host die Drossel. Nach dem Speichern auf der NAS im Ordner von Hivornet ausführen (auch im Aufgabenplaner bzw. in ",
        h("code", null, "tools/hivornet-firewall.service"), " eintragen, sonst gilt nach einem Neustart wieder der alte Stand):",
        h("pre", { class: "term" }, d.command)) : null,
      d.platform === "none" ? h("p", { class: "muted" }, "Cowrie ist hier nicht eingerichtet; die Drossel betrifft nur die Cowrie-Ports.") : null);
  };
  show();
  return section("Dauer-Brute-Force", {
    intro: "Manche Bots melden sich stundenlang alle paar Sekunden mit neuen Zugangsdaten an, jede Kombination in einer eigenen Verbindung. " +
      "Der Hive erkennt sie und speichert ab dann fehlgeschlagene Logins und Verbindungen nur noch gesammelt. Zähler je Kombination, angenommene Logins, " +
      "Befehle und Downloads bleiben vollständig. Eigene Netze und „Nie sperren“ (Weitergabe → Blockliste) sind immer ausgenommen.",
    saveLabel: "Dauer-Brute-Force speichern",
    save: async () => { await ex.save(["brute"]); await show(); },
  },
  row("Erkennen ab", h("div", null, ex.num(b, "min_logins", 20, 100000, 10), " Logins über mindestens ", ex.num(b, "min_minutes", 5, 1440, 5), " Minuten"),
    "Pausen unter 15 Minuten zählen mit (wie bei den Angriffen). Kurze, heftige Angriffe bleiben damit einzeln sichtbar."),
  row("Höchstens", h("div", null, ex.num(b, "max_clients", 1, 20, 1), " verschiedene Clients bzw. HASSH"),
    "Ein Dauer-Brute-Forcer benutzt meist immer dasselbe Werkzeug."),
  row("Verdichten", ex.check(b, "condense", "Fehlgeschlagene Logins erkannter Dauer-Brute-Forcer gesammelt speichern (empfohlen)"),
    "Aus: Der Hive markiert sie nur. Bereits gespeicherte Ereignisse bleiben, wie sie sind."),
  row("Drossel", ex.check(b, "limit", "Neue Verbindungen auf die Cowrie-Ports (SSH, Telnet) je Quell-IP begrenzen"),
    "Die Firewall verwirft überzählige Verbindungsversuche ohne Antwort; der Bot wartet dann bis zu seiner Zeitüberschreitung. Nur die Cowrie-Ports, nie private Adressen, eigene Netze und „Nie sperren“."),
  row("Rate", h("div", null, ex.num(b, "rate", 2, 120, 1), " neue Verbindungen je Minute, Spitze ", ex.num(b, "burst", 5, 1000, 1)),
    "Gewöhnliche Angreifer bleiben darunter. Der Bot aus dem Anlass kam auf etwa 9 je Minute."),
  row("Sperre", h("div", null, ex.num(b, "ban_minutes", 0, 1440, 5), " Minuten nach Überschreiten"),
    "0 = nur drosseln. Mit Sperre bekommt die IP so lange gar keine neue Verbindung zu Cowrie; danach beginnt sie von vorn."),
  state);
}

// ---------- Zusatzfunktionen (/api/extras) ----------
// Ein Bereich schickt seine Schlüssel aus der Arbeitskopie, alles andere aus dem zuletzt
// gespeicherten Stand. Geheimnisse: leer = behalten, „-“ = löschen; jeder Bereich setzt nur seine.

// Geheimnis (Name in der API) -> Ort im Objekt; muss zu secretFields in hive/extras.go passen
// (Test TestExtrasSecretsSentByUI).
const SECRET_AT = {
  ntfy_token: ["notify", "ntfy_token"], telegram_token: ["notify", "telegram_token"],
  ai_api_key: ["ai", "api_key"], mimic_api_key: ["mimic", "api_key"],
  abuseipdb_key: [null, "abuseipdb_key"], greynoise_key: [null, "greynoise_key"], abusech_key: [null, "abusech_key"],
  nvd_key: ["cvedb", "nvd_key"],
  dshield_key: ["dshield", "api_key"],
};
const SECRET_HINT = "gespeichert – leer lassen zum Behalten, „-“ zum Löschen";

async function extrasCtx() {
  const d = await api("extras");
  const x = structuredClone(d.extras);
  x.own = x.own || { private: true, nets: [], in_stats: false };
  x.abuse_report = x.abuse_report || { enabled: false, dry_run: true, daily_limit: 50, interval_hours: 24, skip_scanners: true };
  const ex = { d, x, saved: structuredClone(x), inputs: {} };
  ex.text = (obj, key, attrs = {}) => h("input", { value: obj[key] ?? "", class: "wide", ...attrs, onchange: (e) => { obj[key] = e.target.value.trim(); } });
  ex.num = (obj, key, min, max, step) => h("input", { type: "number", value: obj[key], min, max, step, style: { width: "120px" }, onchange: (e) => { obj[key] = Number(e.target.value); } });
  ex.check = (obj, key, label) => h("label", { class: "inline" }, h("input", { type: "checkbox", checked: !!obj[key], onchange: (e) => { obj[key] = e.target.checked; } }), label);
  ex.secret = (name) => (ex.inputs[name] = h("input", { type: "password", autocomplete: "off", class: "wide", placeholder: d.secrets[name] ? SECRET_HINT : "nicht gesetzt" }));
  // Speichert die Schlüssel keys und die Geheimnisse secrets dieses Bereichs.
  ex.save = async (keys, secrets = []) => {
    const body = structuredClone(ex.saved);
    for (const k of keys) body[k] = structuredClone(ex.x[k]);
    for (const [obj, key] of Object.values(SECRET_AT)) (obj ? body[obj] : body)[key] = "";
    for (const name of secrets) { const [obj, key] = SECRET_AT[name]; (obj ? body[obj] : body)[key] = ex.inputs[name].value.trim(); }
    await api("extras", { method: "PUT", body });
    for (const k of keys) ex.saved[k] = structuredClone(ex.x[k]);
    for (const name of secrets) {
      const inp = ex.inputs[name], v = inp.value.trim();
      if (v) d.secrets[name] = v !== "-";
      inp.value = "";
      inp.placeholder = d.secrets[name] ? SECRET_HINT : "nicht gesetzt";
    }
    if (keys.includes("home")) forgetHome();
  };
  return ex;
}

function homeCard(ex) {
  const x = ex.x;
  return section("Standort für die Live-Karte", {
    intro: "Dorthin zeigen die Angriffslinien auf der Karte. Ein ungefährer Ort genügt; er wird nirgends veröffentlicht.",
    saveLabel: "Standort speichern",
    save: () => ex.save(["home"]),
  },
  row("Breite", ex.num(x.home, "lat", -90, 90, 0.1), "Nordhalbkugel positiv, z. B. 52.5 für Berlin."),
  row("Länge", ex.num(x.home, "lon", -180, 180, 0.1), "Östlich von Greenwich positiv, z. B. 13.4 für Berlin."),
  row("Bezeichnung", ex.text(x.home, "label", { maxlength: 40 })));
}

// ---------- Auswertung und KI ----------

async function tabAuswertung() {
  const ex = await extrasCtx();
  const x = ex.x;
  return [
    section("KI-Auswertung", {
      intro: "Lässt einen Angriffsbericht von einem Sprachmodell in Worte fassen, auf Knopfdruck im Bericht. Funktioniert mit jeder OpenAI-kompatiblen Schnittstelle: lokal mit Ollama oder LM Studio, oder über einen Dienst wie OpenRouter.",
      saveLabel: "KI-Auswertung speichern",
      save: () => ex.save(["ai"], ["ai_api_key"]),
    },
    h("div", { class: "msg warn" }, "Datenschutz: Bei einem Dienst im Internet verlassen IP-Adressen, Zugangsdaten und Befehle der Angreifer dein Netz. Mit einem lokalen Modell bleibt alles im Haus."),
    row("Aktiv", ex.check(x.ai, "enabled", "KI-Auswertung anbieten")),
    row("Adresse", ex.text(x.ai, "base_url", { placeholder: "http://192.168.1.10:11434/v1" }), "Ollama: http://<Rechner>:11434/v1 · OpenRouter: https://openrouter.ai/api/v1"),
    row("Modell", ex.text(x.ai, "model", { placeholder: "llama3.1:8b" }), "Name, wie ihn die Schnittstelle erwartet, z. B. llama3.1:8b; bei OpenRouter der dort angezeigte Modellname."),
    row("API-Schlüssel", ex.secret("ai_api_key"), "Für lokale Modelle meist leer.")).el,

    aiPlusCard(ex),

    section("Antworten vom Sprachmodell", {
      intro: "Kennt die Telnet-Shell des Honeypots einen Befehl nicht oder der Web-Honeypot einen Pfad nicht, erzeugt ein Sprachmodell eine glaubwürdige Antwort. Das hilft gegen Bots, die mit Testbefehlen prüfen, ob die Shell echt ist. Jede Antwort wird gespeichert: Dieselbe Eingabe bekommt immer dieselbe Antwort und kostet nur einmal.",
      saveLabel: "Sprachmodell-Antworten speichern",
      save: () => ex.save(["mimic"], ["mimic_api_key"]),
    },
    h("div", { class: "msg warn" }, "Bei einem Dienst im Internet (z. B. OpenRouter) gehen die Eingaben der Angreifer dorthin und jede neue Antwort kostet Geld. Die Grenzen unten deckeln das; darüber antwortet der Honeypot wie bisher. ",
      "Private Adressen und die öffentliche Adresse des Anschlusses werden vorher durch Platzhalter ersetzt; die öffentliche allerdings nur, wenn sie unter System bei „Wie Shodan dich sieht“ einmal abgefragt wurde. Die IP des Angreifers und der Host-Kopf gehen nie hinaus."),
    row("Aktiv", ex.check(x.mimic, "enabled", "Sprachmodell-Antworten einschalten")),
    row("Wofür", [ex.check(x.mimic, "shell", "unbekannte Befehle der Telnet-Shell"), " ", ex.check(x.mimic, "web", "unbekannte Pfade des Web-Honeypots")]),
    row("Adresse", ex.text(x.mimic, "base_url", { placeholder: "leer = wie KI-Auswertung" }), "Eigene Schnittstelle, z. B. https://openrouter.ai/api/v1. Leer: Adresse und Schlüssel der KI-Auswertung."),
    row("Modell", ex.text(x.mimic, "model", { placeholder: "leer = wie KI-Auswertung" }), "Ein kleines, schnelles Modell genügt; der Angreifer wartet höchstens 10 Sekunden; langsamere Antworten werden im Hintergrund fertig erzeugt und beim nächsten gleichen Befehl verwendet."),
    row("API-Schlüssel", ex.secret("mimic_api_key"), "Nur nötig, wenn oben eine eigene Adresse steht."),
    row("Höchstens pro Stunde", ex.num(x.mimic, "max_per_hour", 1, 5000, 1), "Neue Anfragen ans Modell insgesamt; gespeicherte Antworten zählen nicht."),
    row("Je Angreifer pro Stunde", ex.num(x.mimic, "max_per_ip_hour", 1, 500, 1)),
    row("Höchstens pro Tag", ex.num(x.mimic, "max_per_day", 1, 50000, 1), "Tagesbudget für neue Anfragen ans Modell; deckelt die Kosten auch bei gezielten Versuchen, den Speicher zu umgehen."),
    h("h3", null, "Stand"),
    mimicStatusBox()).el,

    section("Nachschlagen bei Dritten", {
      intro: "Schlüssel für Abfragen auf Knopfdruck, auf der Seite eines Angreifers und im Angriffsbericht. Den AbuseIPDB-Schlüssel gibt es unter „Weitergabe und Meldungen“; er dient auch zum Nachschlagen.",
      saveLabel: "Schlüssel speichern",
      save: () => ex.save([], ["greynoise_key", "abusech_key"]),
    },
    row("GreyNoise", ex.secret("greynoise_key"), "Zeigt, ob eine IP als Massen-Scanner oder harmloser Dienst (z. B. Suchmaschine) bekannt ist. Geht ohne Schlüssel mit kleinem Tageskontingent; ein kostenloser Schlüssel von greynoise.io erhöht es."),
    row("URLhaus und MalwareBazaar", ex.secret("abusech_key"), "Auth-Key von auth.abuse.ch: schlägt Nachlade-Adressen und Datei-Hashes nach. Es wird nichts hochgeladen; abuse.ch sieht nur die abgefragte Adresse bzw. den Hash.")).el,

    section("Lückendetails (CVE)", {
      intro: "Zeigt zu erkannten Lücken CVSS, Beschreibung, EPSS und ob die Lücke im CISA-Katalog der ausgenutzten Lücken (KEV) steht. Der Katalog wird einmal am Tag geladen; NVD und FIRST werden je Lücke gefragt und die Antworten zwischengespeichert. Hinaus gehen nur CVE-Nummern.",
      saveLabel: "Lückendetails speichern",
      save: () => ex.save(["cvedb"], ["nvd_key"]),
    },
    row("Aktiv", ex.check(x.cvedb, "enabled", "Lückendetails von CISA KEV, NVD und FIRST EPSS laden")),
    row("NVD-Schlüssel", ex.secret("nvd_key"), "Optional. Ohne Schlüssel fragt Hivornet die NVD höchstens alle 7 Sekunden; ein kostenloser Schlüssel (nvd.nist.gov) erlaubt eine Abfrage je Sekunde."),
    cveStatusBox()).el,
  ];
}

// Stand der Lückendetails (hive/cvedb.go)
function cveStatusBox() {
  const box = h("div", { class: "muted", "data-nodirty": "" }, "Lade …");
  const load = () => api("cve/status").then((d) => mount(box,
    h("p", { class: "muted" }, d.kev_count ? `CISA KEV: ${fmtNum(d.kev_count)} Einträge, Stand ${d.kev_version || fmtDateTime(d.kev_updated)}, zuletzt geprüft ${relTime(d.kev_checked)}. ` : "CISA KEV noch nicht geladen. ",
      `Seit dem Start ${fmtNum(d.asked)} Lücken bei NVD und FIRST nachgeschlagen, ${fmtNum(d.pending)} ausstehend.`,
      d.kev_error ? h("span", { class: "warn-text" }, " KEV: " + d.kev_error) : null,
      d.last_error ? h("span", { class: "warn-text" }, " Letzter Fehler: " + d.last_error) : null),
    d.enabled ? h("button", { class: "btn small", onclick: async (e) => {
      e.target.disabled = true;
      try { await api("cve/refresh", { method: "POST" }); setTimeout(load, 4000); } catch (err) { alert(err.message); e.target.disabled = false; }
    } }, "KEV jetzt neu laden") : null)).catch((e) => mount(box, h("span", { class: "warn-text" }, e.message)));
  load();
  return box;
}

// Weitere KI-Funktionen (hive/aiplus.go): je Funktion ein Schalter, ein gemeinsames Tagesbudget.
function aiPlusCard(ex) {
  const p = ex.x.ai_plus = ex.x.ai_plus || { max_per_day: 40, brief_per_day: 15 };
  return section("Weitere KI-Funktionen", {
    intro: "Zusätzliche Auswertungen mit Adresse, Modell und Schlüssel der KI-Auswertung oben. Jede Funktion ist einzeln schaltbar und zunächst aus; alle zusammen teilen sich ein Tagesbudget.",
    saveLabel: "KI-Funktionen speichern",
    save: async () => { await ex.save(["ai_plus"]); aiStatusReset(); },
  },
  h("div", { class: "msg warn" }, "Die Daten gehen an den Anbieter des Modells, bei einem Dienst im Internet also aus deinem Netz: Wochenzahlen, Befehle, Pfade, nachgeladene Skripte und Herkunftsländer der Angreifer. ",
    "Die IP des Angreifers geht bei der Kurzanalyse nicht mit; private Adressen und die öffentliche Adresse des Anschlusses werden durch Platzhalter ersetzt, Anweisungen an eine KI in Angreiferdaten vorher entfernt. ",
    "Die Antworten erscheinen nur als Text und lösen nichts aus."),
  row("KI-Wochenbericht", ex.check(p, "weekly", "Woche zusammenfassen: neu, gefährlich, was zu tun ist"),
    "Oben unter Erkenntnisse, dort auch auf Knopfdruck neu. Ist der Wochenbericht unter „Weitergabe und Meldungen“ an, kommt die Zusammenfassung montags mit."),
  row("Kurzanalyse", [ex.check(p, "brief", "schwere Angriffe automatisch kurz analysieren"), " ", ex.check(p, "brief_notify", "auch als Benachrichtigung schicken")],
    "Für Angriffe mit ausgeführten Befehlen, Downloads oder einem schweren Muster: Ziel, Werkzeuge und Gefahr in zwei bis vier Sätzen, in der Angriffskarte und im Bericht. Ähnliche Angriffe (gleiche Angriffsfamilie) übernehmen die Analyse ohne neuen Aufruf."),
  row("Suche in Alltagssprache", ex.check(p, "search", "Fragen in die Suchsprache übersetzen (Seite Angriffe)"),
    "Das Modell sieht nur die Feldliste und deine Frage, keine Angriffsdaten. Die übersetzte Suche wird angezeigt und erst nach deinem Klick angewendet."),
  row("Skripte erklären", ex.check(p, "explain", "Knopf „Mit KI erklären“ für Befehle und nachgeladene Skripte"),
    "Schritt für Schritt, gefährliche Schritte hervorgehoben; je Inhalt nur einmal gefragt, danach aus dem Speicher."),
  row("Tagesbudget", ex.num(p, "max_per_day", 1, 5000, 1), "Höchstens so viele Aufrufe ans Modell je Tag für alle Funktionen dieses Bereichs zusammen."),
  row("Davon Kurzanalysen", ex.num(p, "brief_per_day", 1, 5000, 1), "Damit die automatischen Analysen das Budget nicht allein aufbrauchen."),
  h("h3", null, "Stand"),
  aiPlusStatusBox()).el;
}

function aiPlusStatusBox() {
  const box = h("div", { class: "muted", "data-nodirty": "" }, "Lade …");
  api("ai/status").then((d) => mount(box,
    d.ai_enabled ? null : h("div", { class: "msg warn" }, "Die KI-Auswertung oben ist nicht eingerichtet; ohne sie bleiben diese Funktionen aus."),
    h("p", { class: "muted" }, `Heute: ${fmtNum(d.used_today)} von ${fmtNum(d.max_per_day)} Aufrufen, davon ${fmtNum(d.briefs_today)} Kurzanalysen. `,
      `Seit dem Start: ${fmtNum(d.calls)} Aufrufe, ${fmtNum(d.failed)} fehlgeschlagen. `,
      `Schutz: ${fmtNum(d.cleaned)} Zeilen mit Anweisungen an eine KI nicht weitergegeben, ${fmtNum(d.rejected)} verräterische Antworten verworfen.`,
      d.last_error ? h("span", { class: "warn-text" }, " Letzter Fehler: " + d.last_error) : null))).catch((e) => mount(box, e.message));
  return box;
}

// Stand der Sprachmodell-Antworten (hive/mimic.go)
function mimicStatusBox() {
  const box = h("div", { class: "muted", "data-nodirty": "" }, "Lade …");
  const load = () => api("mimic/status").then((d) => mount(box,
    h("p", { class: "muted" }, `Gespeichert: ${fmtNum(d.cached)} Antworten, zusammen ${fmtNum(d.cache_hits_total)}-mal wiederverwendet. `,
      `Seit dem Start: ${fmtNum(d.asked)} Anfragen ans Modell, ${fmtNum(d.hits)} aus dem Speicher, ${fmtNum(d.limited)} wegen Grenze statisch, ${fmtNum(d.failed)} fehlgeschlagen. `,
      `Schutz: ${fmtNum(d.blocked || 0)} Manipulationsversuche nicht ans Modell gegeben, ${fmtNum(d.rejected || 0)} verräterische Antworten verworfen.`,
      d.last_error ? h("span", { class: "warn-text" }, " Letzter Fehler: " + d.last_error) : null),
    d.recent.length ? h("details", null, h("summary", null, "Zuletzt erzeugt"),
      h("ul", { class: "mono-list" }, d.recent.map((r) => h("li", null, `[${r.kind}] ${r.input}`, r.hits ? h("span", { class: "muted" }, ` · ${fmtNum(r.hits)}× wiederverwendet`) : null)))) : null,
    h("button", { class: "btn small", onclick: async () => {
      if (!confirm("Alle gespeicherten Antworten löschen? Sinnvoll nach einem Wechsel des Geräteprofils.")) return;
      await api("mimic/cache", { method: "DELETE" }); load();
    } }, "Gespeicherte Antworten löschen"))).catch((e) => mount(box, e.message));
  load();
  return box;
}

// ---------- Weitergabe und Meldungen ----------

async function tabWeitergabe() {
  const ex = await extrasCtx();
  const x = ex.x, n = x.notify, st = ex.d.notify_status || {};
  const notify = section("Benachrichtigungen", {
    intro: "Meldung aufs Handy oder an einen Webhook, wenn etwas Wichtiges passiert. Je Angreifer und Anlass höchstens eine Meldung in 10 Minuten.",
    saveLabel: "Benachrichtigungen speichern",
    save: () => ex.save(["notify"], ["ntfy_token", "telegram_token"]),
  },
  row("Aktiv", ex.check(n, "enabled", "Benachrichtigungen senden")),
  row("ntfy-Adresse", ex.text(n, "ntfy_url", { placeholder: "https://ntfy.sh/mein-geheimes-thema" }), "Vollständige Adresse des Themas. Bei ntfy.sh ist der Themenname das einzige Geheimnis: lang und zufällig wählen."),
  row("ntfy-Token", ex.secret("ntfy_token"), "Nur für geschützte Themen oder einen eigenen ntfy-Server."),
  row("Telegram-Bot-Token", ex.secret("telegram_token"), "Vom BotFather."),
  row("Telegram-Chat-ID", ex.text(n, "telegram_chat", { maxlength: 64 })),
  row("Webhook-Adresse", ex.text(n, "webhook_url", { placeholder: "https://…" }), "Bekommt JSON mit title, text, kind, ip und time (z. B. für Home Assistant oder Discord)."),
  row("Anlässe", h("div", { class: "checklist" },
    ex.check(n, "on_login", "Erfolgreicher Login (Cowrie)"),
    ex.check(n, "on_download", "Datei geladen"),
    ex.check(n, "on_severe", "Schweres Angriffsmuster (Nachladen, Miner, Übernahme)"),
    ex.check(n, "on_command", "Erster Befehl einer Sitzung"),
    ex.check(n, "on_warning", "Kritische Systemwarnung (Sensor still, Netzsperre fehlt)"),
    ex.check(n, "on_spike", "Ungewöhnlich viele Angriffe auf einen Dienst (Spitze)"),
    ex.check(n, "weekly_report", "Wochenbericht (montags ab 8 Uhr)"))),
  row("Höchstens pro Stunde", ex.num(n, "max_per_hour", 1, 500, 1), "Darüber wird nur gezählt."),
  h("details", null, h("summary", null, "Vorschau des Wochenberichts (letzte 7 Tage)"), weeklyBox()),
  h("p", { class: "muted" }, `Bisher gesendet: ${fmtNum(st.sent)}, unterdrückt: ${fmtNum(st.suppressed)}.`,
    st.last_error ? h("span", { class: "warn-text" }, " Letzter Fehler: " + st.last_error) : null));
  const testBtn = h("button", { class: "btn small", onclick: async () => {
    if (notify.isDirty()) { notify.say("Erst speichern, dann testen: Die Testnachricht nutzt die gespeicherten Einstellungen.", "err"); return; }
    try { await api("extras/test-notify", { method: "POST" }); notify.say("Testnachricht gesendet.", "ok"); }
    catch (e) { notify.say("Senden fehlgeschlagen: " + e.message, "err"); }
  } }, "Testnachricht senden");
  notify.el.querySelector(".card-foot").prepend(testBtn);

  const ar = x.abuse_report;
  const abuse = section("AbuseIPDB", {
    intro: "Mit einem kostenlosen Schlüssel von abuseipdb.com lässt sich auf der Seite eines Angreifers nachsehen, wie oft seine IP weltweit gemeldet wurde, und Angreifer lassen sich automatisch melden.",
    saveLabel: "AbuseIPDB speichern",
    save: () => ex.save(["abuse_report"], ["abuseipdb_key"]),
  },
  row("API-Schlüssel", ex.secret("abuseipdb_key")),
  h("h3", null, "Angreifer automatisch melden"),
  h("p", { class: "sub" }, "Meldet echte Angriffsversuche (Login-Versuche, Exploits, Befehle, Downloads), damit andere sie blockieren können. ",
    "Nie gemeldet werden eigene und private Adressen, Angriffe nur über UDP (Absender fälschbar) und reines Abtasten. ",
    "Der Kommentar enthält keine Passwörter, keine IP-Adressen und keine Hostnamen des Honeypots."),
  row("Aktiv", ex.check(ar, "enabled", "Automatisch melden")),
  row("Probemodus", ex.check(ar, "dry_run", "Nur protokollieren, was gemeldet würde (nichts senden)"), "Zum Ausprobieren: erst eine Weile im Probemodus laufen lassen und das Protokoll unten ansehen."),
  row("Höchstens pro Tag", ex.num(ar, "daily_limit", 1, 1000, 1), "Das kostenlose Kontingent von AbuseIPDB liegt bei 1.000 Meldungen am Tag."),
  row("Abstand je IP (Stunden)", ex.num(ar, "interval_hours", 1, 720, 1), "AbuseIPDB nimmt dieselbe IP höchstens alle 15 Minuten an."),
  row("Ausnahmen", h("div", { class: "checklist" },
    ex.check(ar, "skip_scanners", "Forschungsscanner (Shodan, Censys, Shadowserver …) nicht melden"),
    ex.check(ar, "include_web_probe", "Auch die Suche nach .env, .git und Anmeldeseiten als Web-Angriff melden"))),
  h("details", null, h("summary", null, "Protokoll der Meldungen"), await abuseLogBox()));

  return [notify.el, abuse.el, ...(await shareCards(ex)), feedCard().el];
}

// ---------- Weitergabe an die Community (hive/share.go, samplecollect.go, dshield.go) ----------
// Je Dienst ein Bereich mit eigenem Speichern; Protokolle aus /api/share/status.

const SHARE_ST = { ok: ["gesendet", "ok"], dry: ["Probe", ""], error: ["Fehler", "err"], known: ["bekannt", "ok"], skipped: ["übersprungen", ""] };

function shareLogTable(ch, subjectLabel, okText) {
  if (!ch) return h("div", { class: "empty" }, "Noch nichts.");
  return h("div", null,
    h("p", { class: "muted" }, `Letzte 24 Stunden: ${fmtNum(ch.ok_24h)} ${okText}`,
      ch.last_run ? ` · zuletzt geprüft ${new Date(ch.last_run).toLocaleTimeString("de-DE")}` : ""),
    ch.pause_until ? h("div", { class: "msg warn" }, "Pausiert bis " + new Date(ch.pause_until).toLocaleString("de-DE") + ".") : null,
    ch.last_error ? h("div", { class: "msg err" }, "Letzter Fehler: " + ch.last_error) : null,
    ch.log.length ? h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Zeit", subjectLabel, "Status", "Hinweis"].map((t) => h("th", null, t)))),
      h("tbody", null, ch.log.slice(0, 50).map((e) => {
        const [label, cls] = SHARE_ST[e.status] || [e.status, ""];
        return h("tr", null,
          h("td", { class: "num" }, new Date(e.time).toLocaleString("de-DE")),
          h("td", { class: "mono", style: { wordBreak: "break-all" } }, e.subject),
          h("td", null, h("span", { class: "badge " + cls }, label)),
          h("td", null, e.error || e.detail || ""));
      })))) : h("div", { class: "empty" }, "Noch keine Einträge."));
}

function quarantineTable(q) {
  if (!q || !q.files.length) return h("div", { class: "empty" }, "Die Quarantäne ist leer.");
  return h("div", null,
    h("p", { class: "muted" }, `${q.files.length === 1 ? "1 Datei" : fmtNum(q.files.length) + " Dateien"}, ${fmtBytes(q.bytes)} von höchstens ${fmtBytes(q.max_bytes)}. `,
      "Angezeigt werden nur Hash und Merkmale; die Dateien selbst gibt die Web-UI nie heraus."),
    h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Geholt", "SHA-256", "Typ", "Größe", "Server", "MalwareBazaar"].map((t) => h("th", null, t)))),
      h("tbody", null, q.files.map((f) => h("tr", null,
        h("td", { class: "num" }, new Date(f.time).toLocaleString("de-DE")),
        h("td", { class: "mono", style: { wordBreak: "break-all" } }, f.sha256),
        h("td", null, [f.type, f.arch].filter(Boolean).join(", ") || "–"),
        h("td", { class: "num" }, fmtBytes(f.size)),
        h("td", { class: "mono" }, f.host || "–"),
        h("td", null, ({ ok: "hochgeladen", known: "bekannt", dry: "Probe", skipped: "nicht hochgeladen" })[f.bazaar] || "–")))))));
}

async function shareCards(ex) {
  const x = ex.x;
  let st = null;
  try { st = await api("share/status"); } catch (e) { /* Protokolle fehlen dann nur */ }
  const noKey = () => st && !st.abusech_key ? h("div", { class: "msg warn" }, "Kein abuse.ch-Schlüssel hinterlegt. Eintragen unter „Auswertung und KI“ → „Nachschlagen bei Dritten“; derselbe Schlüssel dient für URLhaus und MalwareBazaar.") : null;

  const uh = x.urlhaus_report;
  const urlhaus = section("URLhaus: Nachlade-Adressen melden", {
    intro: "Meldet Adressen, von denen Angreifer Schadsoftware nachladen wollten, an URLhaus (abuse.ch). Von dort gelangen sie in Blocklisten von Providern, Browsern und Virenscannern.",
    saveLabel: "URLhaus speichern",
    save: () => ex.save(["urlhaus_report"]),
  },
  noKey(),
  h("p", { class: "sub" }, "Gemeldet werden nur Adressen aus ausgeführten Befehlen (wget, curl, tftp …) und aus Downloads, jede nur einmal. ",
    "Nie gemeldet werden private und eigene Adressen, Rückruf-Adressen von Scannern (interactsh, Burp …), Funde von Forschungsscannern und eigene Tests. ",
    "URLhaus nimmt nur Adressen an, die gerade Schadsoftware ausliefern; wer wiederholt Falsches meldet, kann gesperrt werden."),
  row("Aktiv", ex.check(uh, "enabled", "Nachlade-Adressen automatisch melden")),
  row("Probemodus", ex.check(uh, "dry_run", "Nur protokollieren, was gemeldet würde (nichts senden)")),
  row("Nur bestätigte", ex.check(uh, "verified_only", "Nur Adressen melden, deren Datei der Hive selbst geholt und als Schadsoftware erkannt hat (Programm oder eindeutiges Schadskript)"),
    "Empfohlen. Setzt „Dateien sammeln“ voraus; ftp- und tftp-Adressen werden dann nie gemeldet."),
  row("Höchstens pro Tag", ex.num(uh, "daily_limit", 1, 150, 1)),
  h("details", null, h("summary", null, "Protokoll der Meldungen"), shareLogTable(st && st.urlhaus, "Adresse", "gemeldet")));

  const sc = x.samples;
  const samples = section("Dateien sammeln (Quarantäne)", {
    intro: "Holt die Datei einer Nachlade-Adresse selbst, legt sie in eine Quarantäne und wertet sie aus wie die Downloads von Cowrie. Nur so lassen sich Adressen bestätigen und Proben an MalwareBazaar geben.",
    saveLabel: "Sammeln speichern",
    save: () => ex.save(["samples"]),
  },
  h("div", { class: "msg warn" }, "Der Hive verbindet sich dafür selbst mit dem Server des Angreifers und verrät ihm dabei seine öffentliche IP-Adresse. ",
    "Die kennt der Angreifer ohnehin, denn er greift sie ja an. Honeypot und Cowrie bleiben weiter ohne Internet."),
  h("p", { class: "sub" }, "Schutz: nur http und https; vor jeder Verbindung (auch nach Weiterleitungen und neuer Namensauflösung) wird geprüft, dass das Ziel ",
    "weder im Heimnetz noch sonst privat, lokal oder die eigene Adresse ist. Größe und Zeit sind begrenzt, HTML-Seiten werden verworfen. ",
    "Dateien heißen nur nach ihrem SHA-256, sind nicht ausführbar und werden nie entpackt, ausgeführt oder über die Web-UI ausgeliefert."),
  st && !st.own_ip_known ? h("div", { class: "msg" }, "Die eigene öffentliche Adresse ist noch unbekannt. Unter System → „Wie Shodan dich sieht“ einmal abfragen; dann holt und meldet der Hive sie nie.") : null,
  row("Aktiv", ex.check(sc, "enabled", "Dateien von Nachlade-Adressen holen")),
  row("Downloads pro Tag", ex.num(sc, "daily_limit", 1, 100, 1), "Jeder Versuch zählt, auch ein gescheiterter."),
  row("Je Server und Tag", ex.num(sc, "per_host_daily", 1, 20, 1)),
  row("Größe je Datei (MB)", ex.num(sc, "max_mb", 1, 32, 1)),
  row("Aufbewahrung (Tage)", ex.num(sc, "keep_days", 1, 365, 1)),
  row("Platz insgesamt (MB)", ex.num(sc, "max_total_mb", 10, 10000, 10), "Darüber werden die ältesten Dateien gelöscht."),
  row("User-Agent", ex.text(sc, "user_agent", { maxlength: 120 }), "Wie ein gewöhnliches Werkzeug, z. B. Wget/1.21.4 oder curl/8.5.0. Keine Angaben, die auf dich hinweisen."),
  h("details", null, h("summary", null, "Quarantäne"), quarantineTable(st && st.quarantine)),
  h("details", null, h("summary", null, "Protokoll der Downloads"), shareLogTable(st && st.sample, "Adresse", "geholt")));

  const bz = x.bazaar;
  const bazaar = section("MalwareBazaar: Proben teilen", {
    intro: "Schlägt den Hash gesammelter Dateien bei MalwareBazaar (abuse.ch) nach und lädt unbekannte Schadprogramme hoch, damit Virenscanner sie erkennen.",
    saveLabel: "MalwareBazaar speichern",
    save: () => ex.save(["bazaar"]),
  },
  noKey(),
  h("p", { class: "sub" }, "Hochgeladen werden nur frisch geholte Programme (ELF, Windows) und Skripte mit eindeutig schädlichen Mustern, nie Text, HTML oder Archive. ",
    "Tags: honeypot, Dateityp und Architektur. Die Probe stammt vom Angreifer und enthält nichts über dich."),
  row("Nachschlagen", ex.check(bz, "lookup", "Hash gesammelter Dateien nachschlagen")),
  row("Hochladen", ex.check(bz, "upload", "Unbekannte Schadprogramme hochladen")),
  row("Probemodus", ex.check(bz, "dry_run", "Nur protokollieren, was hochgeladen würde")),
  h("details", null, h("summary", null, "Protokoll"), shareLogTable(st && st.bazaar, "SHA-256", "erledigt")));

  const ds = x.dshield;
  const dshield = section("DShield (SANS Internet Storm Center)", {
    intro: "Sendet stündlich Verbindungsversuche, Web-Anfragen und SSH-/Telnet-Anmeldungen an DShield. Daraus entstehen die weltweiten Angriffsstatistiken und Blocklisten des ISC.",
    saveLabel: "DShield speichern",
    save: () => ex.save(["dshield"], ["dshield_key"]),
  },
  h("p", { class: "sub" }, "Konto unter isc.sans.edu anlegen; Benutzernummer und API-Schlüssel stehen dort unter „My Account“. ",
    "Die eigene Adresse wird nie gesendet (Ziel immer 0.0.0.0), ebenso keine Absender aus dem eigenen Netz. In Pfaden werden eigene IP und Hostnamen ersetzt."),
  row("Aktiv", ex.check(ds, "enabled", "Daten an DShield senden")),
  row("Probemodus", ex.check(ds, "dry_run", "Nur protokollieren, wie viel gesendet würde")),
  row("Benutzernummer", ex.num(ds, "user_id", 0, 999999999, 1)),
  row("API-Schlüssel", ex.secret("dshield_key")),
  row("Was senden", h("div", { class: "checklist" },
    ex.check(ds, "firewall", "Verbindungsversuche (wie ein Firewall-Protokoll)"),
    ex.check(ds, "web", "Web-Anfragen (ohne Host-Kopfzeile)"),
    ex.check(ds, "logins", "SSH- und Telnet-Anmeldeversuche mit Benutzername und Passwort"))),
  h("details", null, h("summary", null, "Protokoll der Sendungen"), shareLogTable(st && st.dshield, "Umfang", "Sendungen")));

  return [urlhaus.el, samples.el, bazaar.el, dshield.el];
}

const ABUSE_CAT = { 5: "FTP-Brute-Force", 11: "E-Mail-Spam", 14: "Port-Scan", 15: "Hacking", 16: "SQL-Injection", 18: "Brute-Force", 20: "Befallener Rechner", 21: "Web-App-Angriff", 22: "SSH", 23: "IoT" };
async function abuseLogBox() {
  let d;
  try { d = await api("abuse/log"); } catch (e) { return h("div", { class: "msg err" }, e.message); }
  const st = { ok: "gemeldet", dry: "würde melden", error: "Fehler" };
  return h("div", null,
    h("p", { class: "muted" }, `Letzte 24 Stunden gemeldet: ${fmtNum(d.sent_24h)}`,
      d.remaining >= 0 ? ` · Kontingent bei AbuseIPDB: noch ${fmtNum(d.remaining)} von ${fmtNum(d.limit)}` : "",
      d.last_run ? ` · zuletzt geprüft ${new Date(d.last_run).toLocaleTimeString("de-DE")}` : ""),
    d.pause_until ? h("div", { class: "msg warn" }, "Pausiert bis " + new Date(d.pause_until).toLocaleString("de-DE") + " (Kontingent erschöpft).") : null,
    d.last_error ? h("div", { class: "msg err" }, "Letzter Fehler: " + d.last_error) : null,
    d.log.length ? h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Zeit", "IP", "Status", "Kategorien", "Kommentar"].map((t) => h("th", null, t)))),
      h("tbody", null, d.log.slice(0, 50).map((e) => h("tr", null,
        h("td", { class: "num" }, new Date(e.time).toLocaleString("de-DE")),
        h("td", null, h("a", { class: "mono", href: "#/attacker/" + encodeURIComponent(e.ip) }, e.ip)),
        h("td", null, h("span", { class: "badge " + (e.status === "ok" ? "ok" : e.status === "error" ? "err" : ""), title: e.error || "" }, st[e.status] || e.status)),
        h("td", null, (e.categories || []).map((c) => ABUSE_CAT[c] || c).join(", ")),
        h("td", { class: "mono" }, e.comment)))))) : h("div", { class: "empty" }, "Noch keine Meldungen."));
}

function weeklyBox() {
  const pre = h("pre", { class: "mono", style: { whiteSpace: "pre-wrap" } }, "Lade …");
  api("weekly").then((d) => { pre.textContent = d.text; }).catch((e) => { pre.textContent = e.message; });
  return pre;
}

// Blockliste zum Abonnieren (hive/feed.go). Einstellungen werden mit „Blockliste speichern“
// übernommen; „Neues Token“ gilt sofort (mit Rückfrage).
const FEED_STUFEN = ["Abtasten (alle)", "Versuche", "Login angenommen", "Befehle ausgeführt", "Datei nachgeladen"];
function feedCard() {
  const body = h("div", { class: "muted" }, "Lade …");
  let saved = null, c = null, info = null;
  const sec = section("Blockliste zum Abonnieren", {
    intro: "Eingeschaltet erzeugt der Hive eine Adresse mit Token, die eine Firewall im Heimnetz regelmäßig abrufen kann, um Angreifer auch vom echten Netz fernzuhalten.",
    saveLabel: "Blockliste speichern",
    save: async () => { load(await api("feed", { method: "PUT", body: c })); },
  }, body);
  const load = (d) => { info = d; saved = d.config; c = structuredClone(saved); render(); };
  const render = () => {
    const d = info;
    const url = location.origin + d.path;
    const sel = (key, opts) => h("select", { onchange: (e) => { c[key] = key === "min_stufe" ? Number(e.target.value) : e.target.value; } },
      opts.map(([v, l]) => h("option", { value: v, selected: String(c[key]) === String(v) }, l)));
    mount(body,
      h("label", { class: "inline" }, h("input", { type: "checkbox", checked: c.enabled, onchange: (e) => { c.enabled = e.target.checked; render(); } }), "Blockliste unter einer eigenen Adresse anbieten"),
      c.enabled ? [
        saved.enabled ? [
          h("div", { class: "form-row" }, h("label", null, "Adresse"),
            h("input", { value: url, readonly: true, class: "mono wide", "data-nodirty": "", onfocus: (e) => e.target.select() }),
            h("div", { class: "help" }, "In der Firewall als URL-Liste eintragen (OPNsense/pfSense: Alias vom Typ „URL Table (IPs)“). Die Adresse enthält ein Token; wer sie kennt, sieht die Liste. Nur im Heimnetz erreichbar wie die Web-UI.")),
          h("div", { class: "btnrow" },
            h("button", { class: "btn small", onclick: () => navigator.clipboard?.writeText(url) }, "Adresse kopieren"),
            h("button", { class: "btn small", onclick: async () => {
              if (!confirm("Neues Token erzeugen? Die alte Adresse funktioniert sofort nicht mehr.")) return;
              try { const keep = c; load(await api("feed", { method: "PUT", body: { ...saved, rotate: true } })); c = { ...keep, token: c.token }; render(); sec.say("Neues Token gilt ab sofort.", "ok"); }
              catch (e) { sec.say(e.message, "err"); }
            } }, "Neues Token (sofort)")),
        ] : h("p", { class: "help" }, "Die Adresse erscheint nach dem Speichern."),
        h("div", { class: "form-row" }, h("label", null, "Zeitraum"), sel("range", [["24h", "24 Stunden"], ["7d", "7 Tage"], ["30d", "30 Tage"]])),
        h("div", { class: "form-row" }, h("label", null, "Ab Stufe"), sel("min_stufe", FEED_STUFEN.map((l, i) => [i, l])),
          h("div", { class: "help" }, "„Versuche“ lässt reines Abtasten weg (das sind oft Forschungsscanner).")),
        h("label", { class: "inline" }, h("input", { type: "checkbox", checked: c.skip_scanners, onchange: (e) => { c.skip_scanners = e.target.checked; } }), "Forschungsscanner und geprüfte Suchmaschinen-Bots auslassen"),
        h("h3", null, "Schutz vor gefälschten Einträgen"),
        h("p", { class: "sub" }, "Wird ein Honeypot übernommen, könnte er Ereignisse mit fremden Adressen fälschen und so Dienste sperren lassen, die du brauchst. ",
          "Deshalb kommen öffentliche DNS-Resolver nie in die Liste, Sensoren mit eigenem Token nur, wenn du ihnen vertraust (Zugang und Sicherheit → Weitere Sensoren), und je Stunde nur begrenzt viele neue Adressen."),
        h("div", { class: "form-row" }, h("label", null, "Nie sperren"),
          h("textarea", { rows: 4, class: "mono wide", placeholder: "z. B. die feste IP deines VPN-Anbieters\n203.0.113.0/24",
            onchange: (e) => { c.never_block = e.target.value.split("\n").map((v) => v.trim()).filter(Boolean); } }, (c.never_block || []).join("\n")),
          h("div", { class: "help" }, "Eine Adresse oder ein Netz (CIDR) je Zeile. Gilt auch für die automatische Meldung an AbuseIPDB.")),
        h("div", { class: "form-row" }, h("label", null, "Neue Adressen je Stunde"),
          h("input", { type: "number", min: 1, max: 100000, value: c.max_new_per_hour, style: { width: "120px" }, onchange: (e) => { c.max_new_per_hour = Number(e.target.value); } }),
          h("div", { class: "help" }, "Darüber hält der Hive neue Adressen zurück und warnt (Systemwarnung).")),
        d.held ? h("div", { class: "msg warn" }, `Zuletzt ${fmtNum(d.held)} neue Adressen zurückgehalten. Kommen ungewöhnlich viele Angreifer auf einmal, prüfe die Sensoren.`) : null,
        d.untrusted ? h("p", { class: "muted" }, `${fmtNum(d.untrusted)} Sensor(en) mit eigenem Token speisen die Liste nicht, bis du ihnen vertraust.`) : null,
        saved.enabled ? h("p", { class: "muted" }, d.count != null ? `Derzeit ${fmtNum(d.count)} Adressen` + (d.sample?.length ? ", z. B. " + d.sample.join(", ") : "") + ". Nie enthalten: eigene Netze, private Adressen und Angreifer, die nur über UDP kamen (Absender fälschbar)." : "Anzahl wird berechnet …") : null,
      ] : null);
  };
  api("feed").then(load).catch((e) => mount(body, h("div", { class: "msg err" }, e.message)));
  return sec;
}

// ---------- Zugang und Sicherheit ----------

async function tabZugang() {
  const out = [passwordCard()];
  if (!isAdmin()) return out;
  const [s, ex] = await Promise.all([api("settings"), extrasCtx()]);
  out.push(await usersCard(), sensorTokensCard(), ownNetsCard(ex).el, accessCard(s).el);
  return out;
}

function passwordCard() {
  const pwCur = h("input", { type: "password", autocomplete: "current-password", maxlength: 72, required: true });
  const pwNew = h("input", { type: "password", autocomplete: "new-password", minlength: 10, maxlength: 72, required: true });
  const status = h("span", { class: "save-status", role: "status" });
  async function changePw(e) {
    e.preventDefault();
    try {
      await api("password", { method: "POST", body: { current: pwCur.value, new: pwNew.value } });
      status.className = "save-status ok"; status.textContent = "Passwort geändert. Alle anderen Sitzungen wurden abgemeldet.";
      pwCur.value = pwNew.value = "";
    } catch (ex) { status.className = "save-status err"; status.textContent = ex.message; }
  }
  const box = card(`Eigenes Passwort (${state.user.username})`,
    h("form", { onsubmit: changePw },
      row("Aktuelles Passwort", pwCur), row("Neues Passwort", pwNew, "10 bis 72 Zeichen. Andere angemeldete Geräte werden abgemeldet."),
      h("div", { class: "card-foot" }, status, h("button", { class: "btn primary", type: "submit" }, "Passwort ändern"))));
  box.classList.add("setting");
  return box;
}

async function usersCard() {
  const body = h("tbody");
  const msg = h("div", { class: "msg", hidden: true });
  const show = (text, ok) => { msg.className = "msg " + (ok ? "ok" : "err"); msg.textContent = text; msg.hidden = false; };
  async function load() {
    const list = await api("users");
    body.replaceChildren(...list.map((u) => h("tr", null,
      h("td", null, u.username), h("td", null, u.role === "admin" ? "Admin" : "Nur ansehen"),
      h("td", null, h("button", {
        class: "btn small",
        onclick: async () => {
          if (!confirm(`Benutzer ${u.username} löschen?`)) return;
          try { await api("users/" + encodeURIComponent(u.username), { method: "DELETE" }); await load(); show("Gelöscht.", true); } catch (e) { show(e.message, false); }
        },
      }, "Löschen")))));
  }
  const name = h("input", { maxlength: 32, placeholder: "z. B. gast", autocomplete: "off" });
  const pw = h("input", { type: "password", minlength: 10, maxlength: 72, autocomplete: "new-password" });
  const role = h("select", { "aria-label": "Rolle" }, h("option", { value: "viewer" }, "Nur ansehen"), h("option", { value: "admin" }, "Admin"));
  const add = h("form", {
    class: "filters",
    onsubmit: async (e) => {
      e.preventDefault();
      try {
        await api("users", { method: "POST", body: { username: name.value.trim(), password: pw.value, role: role.value } });
        name.value = pw.value = "";
        await load();
        show("Benutzer angelegt.", true);
      } catch (ex) { show(ex.message, false); }
    },
  }, h("label", { class: "inline" }, "Name", name), h("label", { class: "inline" }, "Passwort", pw), role,
  h("button", { class: "btn", type: "submit" }, "Anlegen"));
  try { await load(); } catch (e) { return h("div", { class: "msg err" }, "Benutzer nicht abrufbar: " + e.message); }
  return card("Benutzer",
    h("p", { class: "sub" }, "Weitere Konten für die Web-UI. „Nur ansehen“ sieht alle Auswertungen, kann aber nichts ändern und keine KI-Auswertung starten. Anlegen und Löschen gelten sofort."),
    h("div", { class: "tablewrap" }, h("table", null, h("thead", null, h("tr", null, h("th", null, "Name"), h("th", null, "Rolle"), h("th", null, ""))), body)),
    h("h3", null, "Neuer Benutzer"), add, msg);
}

// Weitere Sensoren mit eigenem Token (hive/sensortokens.go); jede Aktion gilt sofort.
function sensorTokensCard() {
  const body = h("div", { class: "muted" }, "Lade …");
  const msg = h("div", { class: "msg", hidden: true });
  const nameIn = h("input", { placeholder: "z. B. vps-1", maxlength: 32, style: { width: "200px" }, "aria-label": "Name des Sensors" });
  const show = (cls, ...kids) => { msg.className = "msg " + cls; mount(msg, ...kids); msg.hidden = false; };
  const load = async () => {
    let list;
    try { list = await api("sensor-tokens"); } catch (e) { mount(body, h("div", { class: "msg err" }, e.message)); return; }
    mount(body, list.length ? h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Sensor", "Angelegt", "Zuletzt gemeldet", "Darf Blockliste und AbuseIPDB speisen", ""].map((t) => h("th", null, t)))),
      h("tbody", null, list.map((s) => h("tr", null, h("td", { class: "mono" }, s.name), h("td", { class: "num" }, fmtDateTime(s.created)),
        h("td", null, s.last_used ? relTime(s.last_used) : h("span", { class: "muted" }, "noch nie")),
        h("td", null, h("label", { class: "inline", title: "Ein übernommener Sensor könnte Ereignisse fälschen und so fremde Adressen sperren oder melden lassen. Nur Sensoren freigeben, die du selbst sicher betreibst." },
          h("input", { type: "checkbox", checked: !!s.trusted, onchange: async (e) => {
            try { await api("sensor-tokens/" + encodeURIComponent(s.name) + "/trust", { method: "POST", body: { trusted: e.target.checked } }); show("ok", "Gespeichert."); }
            catch (err) { e.target.checked = !e.target.checked; show("err", err.message); }
          } }), "vertrauen")),
        h("td", null, h("button", { class: "btn small", onclick: async () => {
          if (!confirm(`Token von „${s.name}“ widerrufen? Der Sensor kann danach nichts mehr melden.`)) return;
          try { await api("sensor-tokens/" + encodeURIComponent(s.name), { method: "DELETE" }); show("ok", "Widerrufen."); load(); } catch (e) { show("err", e.message); }
        } }, "Widerrufen")))))))
      : h("p", { class: "muted" }, "Noch keine weiteren Sensoren."));
  };
  const add = h("form", { class: "btnrow", onsubmit: async (e) => {
    e.preventDefault();
    try {
      const d = await api("sensor-tokens", { method: "POST", body: { name: nameIn.value } });
      nameIn.value = "";
      show("ok", h("div", null, h("b", null, `Token für „${d.name}“ (wird nur jetzt angezeigt):`)),
        h("pre", { class: "term" }, `HIVE_URL=http://<Hive über VPN erreichbar>:8089\nHIVORNET_TOKEN=${d.token}\nSENSOR_NAME=${d.name}`),
        h("div", { class: "aw-small" }, "Diese drei Werte in die .env des entfernten Honeypots eintragen. Die Sensor-API (8089) nie ins Internet freigeben, sondern über ein VPN wie WireGuard erreichbar machen."));
      load();
    } catch (err) { show("err", err.message); }
  } }, nameIn, h("button", { class: "btn small", type: "submit" }, "Sensor anlegen"));
  load();
  return card("Weitere Sensoren",
    h("p", { class: "sub" }, "Ein zweiter Honeypot, z. B. auf einem kleinen Server, kann an diesen Hive melden. Jeder bekommt ein eigenes Token, das an seinen Namen gebunden ist und sich einzeln widerrufen lässt. Änderungen hier gelten sofort."),
    body, add, msg);
}

function ownNetsCard(ex) {
  const own = ex.x.own;
  return section("Eigene Netze", {
    intro: "Verbindungen von hier sind eigene Tests: Sie werden gespeichert und sind auf der Seite Angriffe über den Filter „Eigene Tests“ einsehbar, zählen aber nicht in Kennzahlen, Top-Listen, „Gerade aktiv“ und Benachrichtigungen und werden nie gemeldet oder gesperrt. Gilt ab dem Speichern.",
    saveLabel: "Eigene Netze speichern",
    save: () => ex.save(["own"]),
  },
  row("Heimnetz", ex.check(own, "private", "Private Adressen (192.168.x.x, 10.x.x.x, 172.16–31.x.x, fd00::/8 …) sind eigene Tests")),
  row("Weitere Netze", h("textarea", { rows: 3, class: "wide", placeholder: "203.0.113.0/24\n198.51.100.7",
    onchange: (e) => { own.nets = e.target.value.split(/[\s,]+/).map((v) => v.trim()).filter(Boolean); } }, (own.nets || []).join("\n")),
  "Eine Adresse oder ein Netz (CIDR) je Zeile, z. B. die feste IP deines Anschlusses, wenn du von außen testest."),
  row("Trotzdem zählen", ex.check(own, "in_stats", "Eigene Tests in Kennzahlen und Benachrichtigungen mitzählen")));
}

// Zugriff über einen Reverse-Proxy (erlaubte Hostnamen)
function accessCard(s) {
  const area = h("textarea", { rows: 3, maxlength: 4000, spellcheck: false, autocomplete: "off", class: "mono wide", placeholder: "hivornet.example.de" });
  area.value = (s.allowed_hosts || []).join("\n");
  const env = s.allowed_hosts_env || [];
  return section("Zugriff über Reverse-Proxy", {
    intro: "Die Web-UI antwortet nur auf IP-Adressen und Heimnetz-Namen (z. B. .local, .lan, .fritz.box). Das schützt vor DNS-Rebinding. Rufst du sie über einen Reverse-Proxy unter eigener Domain auf, trage diese hier ein, einen Namen pro Zeile. Ein Punkt am Anfang (.example.de) erlaubt alle Unterdomänen.",
    saveLabel: "Hostnamen speichern",
    save: async () => {
      const r = await api("settings", { method: "PUT", body: { allowed_hosts: area.value.split(/[\s,]+/).filter(Boolean) } });
      area.value = r.allowed_hosts.join("\n");
      return r.allowed_hosts.length ? "Gespeichert. Die Namen gelten sofort." : "Gespeichert. Es sind nur noch IP-Adressen und Heimnetz-Namen erlaubt.";
    },
  },
  row("Erlaubte Hostnamen", area, "Nur den Namen, ohne https:// und Port. Über die IP-Adresse bleibt die Web-UI immer erreichbar."),
  env.length ? h("p", { class: "muted" }, "Zusätzlich aus der Konfiguration (HIVE_ALLOWED_HOSTS): " + env.join(", ")) : null,
  h("p", { class: "muted" }, "Das Anmelde-Cookie ist automatisch nur über HTTPS gültig, wenn du dich über HTTPS anmeldest (der Proxy muss dafür X-Forwarded-Proto: https mitschicken). Gib die Web-UI nie ohne zusätzliche Anmeldung am Proxy oder VPN ins Internet frei."));
}

// ---------- Daten und Wartung ----------

async function tabDaten() {
  const s = await api("settings");
  let retention = s.retention_days;
  const out = [section("Aufbewahrung", {
    intro: "Gilt für alle Sensoren. Danach werden Ereignisse und Angreifer-IPs gelöscht; Statistiken ohne IPs bleiben.",
    saveLabel: "Aufbewahrung speichern",
    save: async () => {
      await api("settings", { method: "PUT", body: { retention_days: retention } });
      return `Gespeichert: Rohdaten bleiben ${fmtNum(retention)} Tage.`;
    },
  },
  row("Rohdaten aufbewahren (Tage)", h("input", { type: "number", min: 1, max: 3650, value: retention, style: { width: "110px" }, onchange: (e) => { retention = Number(e.target.value); } }),
    "1 bis 3650 Tage. Wird der Speicher knapp, löscht der Hive die ältesten Ereignisse auch früher.")).el];
  if (isAdmin()) out.push(backupCard()); // Import auch auf einem frisch installierten Gerät
  return out;
}

// Sicherung (Export und Import aller Daten, verschlüsselt)
function backupCard() {
  const msg = h("div", { class: "msg", hidden: true });
  const show = (text, cls) => { msg.className = "msg " + cls; msg.textContent = text; msg.hidden = false; };
  const pwOut = h("input", { type: "password", autocomplete: "current-password", maxlength: 72 });
  const pwIn = h("input", { type: "password", autocomplete: "off", maxlength: 72 });
  const file = h("input", { type: "file", accept: ".hvbak" });
  const btnOut = h("button", { class: "btn", type: "submit" }, "Sicherung herunterladen");
  const btnIn = h("button", { class: "btn", type: "submit" }, "Sicherung einspielen");

  async function doExport(e) {
    e.preventDefault();
    if (!pwOut.value) { show("Bitte dein Passwort eingeben.", "err"); return; }
    btnOut.disabled = true;
    show("Sicherung wird erstellt und verschlüsselt … das kann bei vielen Daten etwas dauern.", "warn");
    try {
      const r = await fetch("api/backup/export", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-Requested-With": "hivornet" },
        body: JSON.stringify({ password: pwOut.value }),
      });
      if (!r.ok) {
        let err = r.statusText;
        try { err = (await r.json()).error || err; } catch { /* leer */ }
        throw new Error(err);
      }
      const blob = await r.blob();
      const name = (/filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") || "") || [])[1] || "hivornet-sicherung.hvbak";
      const url = URL.createObjectURL(blob);
      const a = h("a", { href: url, download: name });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      pwOut.value = "";
      show(`Sicherung gespeichert (${fmtBytes(blob.size)}). Bewahre die Datei sicher auf; zum Einspielen brauchst du dasselbe Passwort.`, "ok");
    } catch (ex) {
      show("Export fehlgeschlagen: " + ex.message, "err");
    } finally { btnOut.disabled = false; }
  }

  // Nach dem Einspielen startet der Hive neu; warten, bis er wieder antwortet.
  async function waitForRestart() {
    await new Promise((r) => setTimeout(r, 3000));
    for (let i = 0; i < 60; i++) {
      try {
        const r = await fetch("healthz", { cache: "no-store" });
        if (r.ok) { location.hash = "#/"; location.reload(); return; }
      } catch { /* startet noch */ }
      await new Promise((r) => setTimeout(r, 2000));
    }
    show("Der Hive meldet sich nicht zurück. Startet er nicht von selbst neu (z. B. ohne Docker oder systemd), bitte von Hand starten.", "err");
  }

  function doImport(e) {
    e.preventDefault();
    const f = file.files && file.files[0];
    if (!f) { show("Bitte eine Sicherungsdatei (.hvbak) auswählen.", "err"); return; }
    if (!pwIn.value) { show("Bitte das Passwort der Sicherung eingeben.", "err"); return; }
    if (!confirm("Alle aktuellen Daten, Einstellungen und Benutzer werden durch die Sicherung ersetzt. Die bisherige Datenbank wird vorher unter backups/ aufgehoben. Fortfahren?")) return;
    const fd = new FormData();
    fd.append("password", pwIn.value); // zuerst: der Hive liest die Felder in dieser Reihenfolge
    fd.append("file", f);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "api/backup/import");
    xhr.setRequestHeader("X-Requested-With", "hivornet");
    xhr.upload.onprogress = (ev) => {
      if (ev.lengthComputable) show(`Lade hoch … ${Math.round((ev.loaded / ev.total) * 100)} %`, "warn");
    };
    xhr.upload.onload = () => show("Entschlüssele und prüfe die Sicherung …", "warn");
    xhr.onload = () => {
      let d = null;
      try { d = JSON.parse(xhr.responseText); } catch { /* leer */ }
      if (xhr.status === 200) {
        pwIn.value = "";
        const m = (d && d.meta) || {};
        show(`Sicherung vom ${m.created ? fmtDateTime(m.created) : "?"} mit ${fmtNum(m.events)} Ereignissen übernommen. Hivornet startet neu; danach meldest du dich mit den Zugangsdaten aus der Sicherung an …`, "ok");
        waitForRestart();
      } else {
        btnIn.disabled = false;
        show("Einspielen fehlgeschlagen: " + ((d && d.error) || xhr.statusText), "err");
      }
    };
    xhr.onerror = () => { btnIn.disabled = false; show("Verbindung abgebrochen.", "err"); };
    btnIn.disabled = true;
    xhr.send(fd);
  }

  return card("Sicherung",
    h("p", { class: "sub" }, "Sichert alles in eine verschlüsselte Datei: Einstellungen, Zusatzfunktionen mit allen API-Schlüsseln, Benutzer sowie alle Angriffe, Statistiken und Berichte. ",
      "So geht nichts verloren, wenn du den Raspberry Pi neu aufsetzt oder auf ein anderes Gerät umziehst. Nicht enthalten sind Cowrie-Mitschnitte und -Downloads."),
    h("h3", null, "Exportieren"),
    h("form", { onsubmit: doExport },
      row("Dein Passwort", pwOut, "Zur Bestätigung. Mit diesem Passwort wird die Datei verschlüsselt; ohne es lässt sie sich nicht einspielen."),
      btnOut),
    h("h3", null, "Importieren"),
    h("form", { onsubmit: doImport },
      row("Sicherungsdatei", file),
      row("Passwort der Sicherung", pwIn, "Das Admin-Passwort, mit dem die Sicherung erstellt wurde."),
      btnIn),
    msg);
}
