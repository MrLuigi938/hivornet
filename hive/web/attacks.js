// Angriffe statt Ereignisse: Ereignisse einer IP werden zu Angriffen gebündelt
// (Lücke unter 15 Minuten, siehe hive/attacks.go). Karte je Angriff mit Stufe,
// vermuteter Art, Zusammenfassung und Zeitstreifen; kompakte Zeile fürs Dashboard.
import { h, mount, api, fmtNum, fmtTime, fmtDur, toMs, relTime, flag, store } from "./dom.js";
import { svcName, svcColor, countryName } from "./charts.js";
import { header, card, TYPE_NAME, rangePicker, rangeOK } from "./app.js";
import { briefBox, loadBriefs, aiSearch } from "./ai.js";

export const STUFE = ["Abtasten", "Versuche", "Login angenommen", "Befehle ausgeführt", "Datei nachgeladen"];
export const STUFE_KURZ = ["Scan", "Versuche", "Login ok", "Befehle", "Download"];
export const sevColor = (n) => `var(--sev${n})`;
const TYPCOL = { connect: "var(--other)", client_version: "var(--other)", tls: "var(--other)", fingerprint: "var(--other)",
  login: "var(--sev1)", request: "var(--s2)", payload: "var(--s7)", command: "var(--sev3)", download: "var(--sev4)", tty: "var(--sev3)", ai_reply: "var(--s7)",
  condensed: "var(--sev1)" };
// Dauer-Brute-Force (hive/bruteforce.go): Erklärung für Merkmal und Filter
export const BRUTE_TITLE = "Dauer-Brute-Force: sehr viele Logins über lange Zeit, meist mit demselben Client. Ab der Erkennung speichert der Hive fehlgeschlagene Logins und Verbindungen nur noch gesammelt; Zähler je Kombination, angenommene Logins und alles danach bleiben vollständig (Einstellungen → Honeypot → Dauer-Brute-Force).";
const RANGES = [["1h", "1 Std"], ["24h", "24 Std"], ["7d", "7 Tage"], ["30d", "30 Tage"], ["90d", "90 Tage"], ["all", "Alles"]];

// Kurzfassung in einer Zeile
export function summary(a) {
  const c = a.counts || {}, p = [];
  if (c.login) p.push(`${fmtNum(c.login)} Login-Versuch${c.login > 1 ? "e" : ""}`);
  if (a.success) p.push("Login angenommen");
  const web = !a.services.every((s) => s === "sip" || s === "dns");
  if (c.request) p.push(web ? `${fmtNum(c.request)} Web-Anfrage${c.request > 1 ? "n" : ""}` : `${fmtNum(c.request)} Anfrage${c.request > 1 ? "n" : ""}`);
  if (c.payload) p.push(`${fmtNum(c.payload)}× Daten`);
  if (c.command) p.push(`${fmtNum(c.command)} Befehl${c.command > 1 ? "e" : ""} ausgeführt`);
  const proto = (c.proto_command || 0) + (c.probe_command || 0);
  if (proto) p.push(`${fmtNum(proto)} Protokoll-Befehl${proto > 1 ? "e" : ""}`);
  if (c.prompt) p.push(`${fmtNum(c.prompt)}× Befehle an der Login-Abfrage`);
  if (c.tls_plain) p.push("TLS-Handshake am Klartext-Port");
  if (c.foreign) p.push(`${fmtNum(c.foreign)}× HTTP oder Binärdaten an fremdem Port`);
  if (c.download) p.push(`${fmtNum(c.download)} Download${c.download > 1 ? "s" : ""}`);
  if (c.ai_reply) p.push(`${fmtNum(c.ai_reply)}× von der KI beantwortet`);
  if (!p.length) p.push(a.ports.length > 1 ? `${a.ports.length} Ports abgetastet` : `Verbindung zu Port ${a.ports[0] || "?"}`);
  return p.join(" · ");
}

const where = (a) => [a.country ? [a.city, a.country_name || countryName(a.country)].filter(Boolean).join(", ") : "Herkunft unbekannt", a.asn ? `AS${a.asn} ${a.as_org || ""}`.trim() : ""].filter(Boolean).join(" · ");
const svcBadges = (a) => a.services.map((sv) => h("span", { class: "badge svc", style: { background: svcColor(sv) } }, svcName(sv)));
const counted = (list, max) => list.slice(0, max).map((x) => (x.n > 1 ? `${x.key} ×${fmtNum(x.n)}` : x.key));

// ---------- Lückendetails (hive/cvedb.go): CVSS, EPSS, KEV ----------

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const cveCache = new Map(); // CVE -> {info, at}
let cveWant = new Map(); // CVE -> [Rückrufe]
let cveTimer = null;

// cveInfo lädt Details gebündelt (eine Anfrage für alle Karten einer Seite) und merkt sie sich
// fünf Minuten; ausstehende Abfragen (NVD gedrosselt) werden nach einer Weile erneut gefragt.
export function cveInfo(id, cb) {
  if (!CVE_RE.test(id)) return;
  const c = cveCache.get(id);
  if (c && Date.now() - c.at < 300e3 && !c.info.pending) { cb(c.info); return; }
  if (!cveWant.has(id)) cveWant.set(id, []);
  cveWant.get(id).push(cb);
  if (!cveTimer) cveTimer = setTimeout(cveFlush, 30);
}

async function cveFlush() {
  const want = cveWant;
  cveWant = new Map();
  cveTimer = null;
  const ids = [...want.keys()];
  for (let i = 0; i < ids.length; i += 100) {
    const part = ids.slice(i, i + 100);
    let d;
    try { d = await api("cve/info?ids=" + part.join(",")); } catch { continue; }
    const again = [];
    for (const id of part) {
      const info = (d.info || {})[id];
      if (!info) continue;
      cveCache.set(id, { info, at: Date.now() });
      for (const cb of want.get(id)) cb(info);
      if (info.pending && d.status && d.status.enabled) again.push(id);
    }
    // nachfragen, solange die Abfrage aussteht (höchstens etwa zwei Minuten je Seite)
    for (const id of again) {
      const cbs = want.get(id).filter((cb) => !cb.tries || cb.tries < 8);
      for (const cb of cbs) cb.tries = (cb.tries || 0) + 1;
      if (cbs.length) setTimeout(() => cbs.forEach((cb) => cveInfo(id, cb)), 15e3);
    }
  }
}

const SEV_CLASS = { CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low" };
// Prozent mit sinnvoller Genauigkeit; knapp unter 100 % nicht auf 100 runden
const pct = (x) => (x >= 0.9995 ? "> 99,9" : (x * 100).toFixed(x >= 0.1 && x < 0.99 ? 0 : x >= 0.01 ? 1 : 2).replace(".", ",")) + " %";
const pctile = (x) => Math.min(99.9, x * 100).toFixed(1).replace(".", ",") + " %";

// Kennzeichen einer CVE: CVSS, EPSS, KEV, Ransomware; Hinweis, solange etwas aussteht.
export function cveBadges(info) {
  if (!info) return [];
  const out = [];
  if (info.cvss) out.push(h("span", { class: "badge cvss " + (SEV_CLASS[info.severity] || ""), title: `CVSS ${info.cvss_version || ""} ${info.vector || ""}`.trim() }, `CVSS ${String(info.cvss).replace(".", ",")}`));
  if (info.epss) out.push(h("span", { class: "badge", title: `EPSS: Wahrscheinlichkeit einer Ausnutzung in den nächsten 30 Tagen (FIRST), höher als bei ${pctile(info.epss_pct)} aller CVEs` }, "EPSS " + pct(info.epss)));
  if (info.kev) out.push(h("span", { class: "badge err", title: `Im CISA-Katalog der ausgenutzten Lücken seit ${info.kev_added || "?"}` }, "KEV"));
  if (info.ransomware) out.push(h("span", { class: "badge err", title: "Laut CISA von Ransomware-Gruppen genutzt" }, "Ransomware"));
  if (info.unknown) out.push(h("span", { class: "badge", title: "Die NVD kennt diese Nummer nicht" }, "unbekannt"));
  else if (info.pending && !info.cvss) out.push(h("span", { class: "muted small" }, "Details werden geladen …"));
  return out;
}

// Ausführliche Angaben zu einer CVE (aufklappbar in Tabelle, Karte und Bericht).
export function cveDetails(id, info) {
  info = info || {};
  const rows = [
    info.kev_name ? ["CISA KEV", `${info.kev_name} (aufgenommen ${info.kev_added || "?"})`] : null,
    info.vendor || info.product ? ["Hersteller / Produkt", [info.vendor, info.product].filter(Boolean).join(" / ")] : null,
    info.published ? ["Veröffentlicht", info.published] : null,
    info.cvss ? ["CVSS", `${String(info.cvss).replace(".", ",")} (${info.severity || "?"}, Version ${info.cvss_version || "?"})${info.vector ? " · " + info.vector : ""}`] : null,
    info.epss ? ["EPSS", `${pct(info.epss)} · höher als bei ${pctile(info.epss_pct)} aller CVEs${info.epss_date ? " · Stand " + info.epss_date : ""}`] : null,
    info.cwe && info.cwe.length ? ["Schwäche", info.cwe.join(", ")] : null,
  ].filter(Boolean);
  const links = [
    ["NVD", "https://nvd.nist.gov/vuln/detail/" + id],
    info.kev ? ["CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=" + id] : null,
    ["EPSS", "https://api.first.org/data/v1/epss?cve=" + id],
    ...(info.refs || []).map((u) => { try { const x = new URL(u); return x.protocol === "https:" ? [x.hostname, u] : null; } catch { return null; } }),
  ].filter(Boolean);
  return h("div", { class: "cve-details" },
    info.desc ? h("p", null, info.desc) : h("p", { class: "muted" }, info.pending ? "Beschreibung wird bei der NVD abgefragt …" : "Keine Beschreibung vorhanden (Lückendetails ausgeschaltet oder NVD ohne Eintrag)."),
    rows.length ? h("dl", null, rows.map(([k, v]) => [h("dt", null, k), h("dd", null, v)])) : null,
    h("p", { class: "cve-links" }, links.map(([t, u]) => h("a", { href: u, target: "_blank", rel: "noopener noreferrer" }, t))));
}

const KIND_LABEL = { exploit: "Ausnutzung", probe: "Probe" };
export const kindChip = (kind) => h("span", { class: "chip" + (kind === "exploit" ? " warn" : ""), title: kind === "exploit" ? "Die Anfrage trägt die Nutzlast der Lücke oder nutzt eine Fehlkonfiguration" : "Prüft nur, ob das Produkt vorhanden ist" }, KIND_LABEL[kind] || kind);

// Regeltreffer eines Angriffs oder Berichts: Art, Produkt, Lücke mit Kennzeichen, Pfad.
export function exploitHits(list) {
  return h("ul", { class: "xp-hits" }, list.map((x) => {
    const badges = h("span", { class: "xp-badges" });
    const more = h("div", { hidden: true });
    let info = null;
    if (x.cve) cveInfo(x.cve, (i) => { info = i; mount(badges, cveBadges(i)); if (!more.hidden) mount(more, cveDetails(x.cve, info)); });
    const toggle = x.cve ? h("button", { class: "linklike", "aria-expanded": "false", onclick: () => {
      more.hidden = !more.hidden;
      toggle.setAttribute("aria-expanded", String(!more.hidden));
      if (!more.hidden) mount(more, cveDetails(x.cve, info));
    } }, x.cve) : h("span", { class: "muted" }, "ohne CVE");
    return h("li", null,
      h("div", { class: "row" }, kindChip(x.kind), h("b", null, x.product), h("span", null, x.name), x.custom ? h("span", { class: "chip", title: "Eigene Regel aus einem KI-Vorschlag" }, "eigene Regel") : null),
      h("div", { class: "row" }, toggle, badges, x.n > 1 ? h("span", { class: "muted" }, fmtNum(x.n) + "×") : null, x.path ? h("code", { class: "mono", title: x.path }, x.path) : null),
      more);
  }));
}

// Ereignis als reiner Text (für zusammengefasste Zeilen)
function evText(e) {
  let d = e.data || {};
  if (typeof d === "string") { try { d = JSON.parse(d); } catch { d = {}; } }
  switch (e.type) {
    case "login": return d.cookie ? `${e.username || "–"} (RDP-Cookie)` : `${e.username || "–"} / ${d.password_hashed ? "(gehasht)" : e.password ?? ""}${d.success || d.accepted ? " ✓ angenommen" : ""}`;
    case "request": return `${d.method || ""} ${d.path || ""}`.trim();
    case "command": return d.input || "";
    case "download": return d.url || "";
    case "client_version": return d.version || "";
    case "payload": return d.text || "";
    case "connect": return `Port ${e.dst_port}`;
    case "tls": return d.sni ? `SNI ${d.sni}` : "TLS";
    case "fingerprint": return d.hassh ? `HASSH ${d.hassh}` : "";
    case "tty": return "Terminal-Mitschnitt";
    case "condensed": {
      const t = d.types || {}, parts = [["login", "Logins"], ["connect", "Verbindungen"]].filter(([k]) => t[k]).map(([k, l]) => `${fmtNum(t[k])} ${l}`);
      return `${fmtNum(d.n || 0)} Ereignisse verdichtet (${parts.join(", ")}) seit ${fmtTime(d.from)}`;
    }
    case "ai_reply": return `${d.input || ""} → ${String(d.output || "").split("\n").find((l) => l.trim()) || "(leer)"}`;
  }
  return "";
}

// Ereignisse eines Angriffs laden und gleichartige direkt hintereinander zusammenfassen
async function attackEvents(a) {
  const evs = await api(`events?src_ip=${encodeURIComponent(a.ip)}&from=${a.first}&to=${a.last}&limit=500`);
  evs.reverse();
  const out = [];
  for (const e of evs) {
    if (e.type === "disconnect") continue;
    const l = out[out.length - 1];
    if (l && l.type === e.type && l.service === e.service && e.type !== "command") { l.items.push(e); continue; }
    out.push({ type: e.type, service: e.service, items: [e] });
  }
  return { groups: out, more: evs.length >= 500 };
}
function eventGroups({ groups, more }) {
  return [groups.map((g) => {
    const kinds = [...new Set(g.items.map(evText))].filter(Boolean);
    return h("div", { class: "evrow" },
      h("span", { class: "num muted" }, fmtTime(g.items[0].ts)),
      h("b", null, TYPE_NAME[g.type] || g.type, " ", h("span", { class: "muted" }, svcName(g.service)), g.items.length > 1 ? h("span", { class: "xn" }, "×" + fmtNum(g.items.length)) : null),
      h("span", { class: "mono" }, kinds.slice(0, 6).join("  ·  ") + (kinds.length > 6 ? `  · +${kinds.length - 6}` : "")));
  }), more ? h("p", { class: "muted" }, "Nur die neuesten 500 Ereignisse; alle unter Angreifer-Profil.") : null];
}

// Antworten des Sprachmodells (Einstellungen → Antworten mit Sprachmodell): Eingabe des
// Angreifers und was der Honeypot daraufhin ausgeliefert hat. Nur Text, nie ausgeführt.
export function aiReplies(list, { max = 3 } = {}) {
  if (!list || !list.length) return null;
  const one = (r) => h("details", { class: "aireply" },
    h("summary", null, h("span", { class: "badge ai" }, r.kind === "web" ? "Web" : "Shell"), " ",
      h("span", { class: "mono" }, r.input), r.status ? h("span", { class: "muted" }, ` · HTTP ${r.status}`) : null,
      r.cached ? h("span", { class: "muted", title: "Aus dem Zwischenspeicher, das Modell wurde nicht erneut gefragt" }, " · gespeichert") : null,
      h("span", { class: "muted" }, " · " + fmtTime(r.t))),
    h("pre", { class: "mono" }, r.output || "(leer)"));
  const box = h("div", { class: "ai-list" }, list.slice(0, max).map(one));
  if (list.length > max) {
    const btn = h("button", { class: "linklike", onclick: () => { mount(box, list.map(one)); btn.remove(); } }, `alle ${list.length} anzeigen`);
    return h("div", null, box, btn);
  }
  return box;
}

// Große Karte (Seite "Angriffe", Angreifer-Profil)
export function attackCard(a, { fresh = false, open = null, showIP = true, brief = null } = {}) {
  const now = Date.now(), active = now - a.last < 60e3, span = Math.max(1, a.last - a.first);
  const evBox = h("div", { class: "evs", hidden: true });
  const toggle = h("button", null, `${fmtNum(a.events)} Ereignisse anzeigen`);
  let loaded = false;
  const setOpen = async (on) => {
    evBox.hidden = !on;
    toggle.textContent = on ? "Ereignisse ausblenden" : `${fmtNum(a.events)} Ereignisse anzeigen`;
    if (open) on ? open.add(a.id) : open.delete(a.id);
    if (on && !loaded) {
      loaded = true;
      mount(evBox, h("p", { class: "muted" }, "Lade …"));
      try { mount(evBox, eventGroups(await attackEvents(a))); } catch (e) { mount(evBox, h("div", { class: "msg err" }, e.message)); loaded = false; }
    }
  };
  toggle.onclick = () => setOpen(evBox.hidden);
  const facts = [
    a.creds && a.creds.length ? ["Zugangsdaten" + (a.creds_distinct > 1 ? ` (${fmtNum(a.creds_distinct)} verschiedene)` : ""), counted(a.creds, 8), a.creds_distinct > 8 ? `+${fmtNum(a.creds_distinct - 8)}` : null] : null,
    a.paths && a.paths.length ? [(a.services.every((s) => s === "sip" || s === "dns") ? "Anfragen" : "Aufgerufene Pfade") + (a.paths_distinct > 1 ? ` (${fmtNum(a.paths_distinct)})` : ""), counted(a.paths, 8), a.paths_distinct > 8 ? `+${fmtNum(a.paths_distinct - 8)}` : null] : null,
    a.commands && a.commands.length ? ["Befehle (ausgeführt)", a.commands.slice(0, 6), a.commands.length > 6 ? `+${a.commands.length - 6}` : null] : null,
    a.proto_commands && a.proto_commands.length ? ["Protokoll-Befehle (ohne Anmeldung)", a.proto_commands.slice(0, 6), a.proto_commands.length > 6 ? `+${a.proto_commands.length - 6}` : null] : null,
    a.urls && a.urls.length ? ["Nachlade-Adressen (nicht aufrufen)", a.urls, null, "hot"] : null,
    a.decoded && a.decoded.length ? ["Entschlüsselt (Base64, Hex …)", a.decoded, null, "decoded"] : null,
    a.tags && a.tags.length ? ["Erkannte Muster", a.tags.map((t) => t.label || t.key), null, "tag"] : null,
    a.cves && a.cves.length && !(a.exploits && a.exploits.length) ? ["Bekannte Lücken", a.cves.map((c) => `${c.key} ${c.label || ""}`.trim()), null, "hot"] : null,
    a.clients && a.clients.length ? ["Client", a.clients, null] : null,
    a.fingerprints && a.fingerprints.length ? ["Fingerabdrücke", a.fingerprints, null] : null,
    a.mitre && a.mitre.length ? ["MITRE ATT&CK", a.mitre, null] : null,
  ].filter(Boolean);
  const el = h("article", { class: "atk" + (fresh ? " fresh" : ""), style: { "--c": sevColor(a.stufe) } },
    h("div", { class: "l1" },
      showIP ? [flag(a.country), h("a", { class: "ip mono", href: "#/attacker/" + encodeURIComponent(a.ip) }, a.ip), h("span", { class: "where" }, where(a))] : null,
      h("div", { class: "right" },
        a.own ? h("span", { class: "badge", title: "Adresse aus einem eigenen Netz (Einstellungen → Eigene Netze)" }, "eigener Test") : null,
        a.brute ? h("span", { class: "badge", title: BRUTE_TITLE }, "Dauer-Brute-Force" + (a.condensed ? ` · ${fmtNum(a.condensed)} verdichtet` : "")) : null,
        a.scanner ? h("span", { class: "badge", title: "Bekannter Forschungs- oder Vermessungsdienst bzw. per DNS geprüfter Suchmaschinen-Bot" }, "Scanner: " + a.scanner) : null,
        a.bot && !a.scanner ? h("span", { class: "badge" + (a.bot.includes("gefälscht") ? " err" : ""), title: "Prüfung per Rückwärts- und Vorwärtsauflösung" }, a.bot) : null,
        a.ai_replies && a.ai_replies.length ? h("span", { class: "badge ai", title: "Das Sprachmodell hat diesem Angreifer geantwortet (Einstellungen → Antworten mit Sprachmodell)" }, "beantwortet durch KI") : null,
        a.seen > 1 ? h("span", { class: "badge" }, `${a.seen}. Angriff dieser IP`) : null,
        active ? h("span", { class: "badge active" }, "● aktiv") : null,
        h("span", { class: "num" }, `${fmtTime(a.first).slice(0, 5)}–${fmtTime(a.last).slice(0, 5)} · ${fmtDur(span)}`),
        h("span", null, relTime(a.last)))),
    h("div", { class: "l2" },
      h("span", { class: "badge stufe" }, STUFE[a.stufe]),
      h("span", { class: "prof" }, a.profile),
      svcBadges(a),
      h("span", { class: "muted" }, summary(a)),
      a.tarpit_ms > 1000 ? h("span", { class: "badge tarpit" }, `festgehalten ${fmtDur(a.tarpit_ms)}`) : null),
    a.strip && a.strip.length > 1 ? h("div", { class: "strip", title: "Jeder Strich ist ein Ereignis; Farbe = Art" },
      a.strip.map((e) => h("i", { style: { left: `calc(${((e.t - a.first) / span) * 100}% - 1px)`, background: TYPCOL[e.type] || "var(--other)" } })),
      h("span", { class: "t", style: { left: 0 } }, fmtTime(a.first)), h("span", { class: "t", style: { right: 0 } }, fmtTime(a.last))) : null,
    brief ? briefBox(brief) : null, // KI-Kurzanalyse (hive/aiplus.go)
    facts.length ? h("div", { class: "facts", style: a.strip && a.strip.length > 1 ? null : { marginTop: "12px" } }, facts.map(([k, items, more, cls]) => h("div", { class: "fact" },
      h("div", { class: "k" }, k),
      h("div", { class: "v" }, items.map((x) => h("span", { class: "pill mono" + (cls ? " " + cls : ""), title: x }, x)), more ? h("span", { class: "muted" }, more) : null)))) : null,
    a.exploits && a.exploits.length ? h("div", { class: "fact xp-fact" }, h("div", { class: "k" }, "Produkte und Lücken (Pfad → Produkt → CVE)"), exploitHits(a.exploits)) : null,
    a.ai_replies && a.ai_replies.length ? h("div", { class: "fact ai-fact" }, h("div", { class: "k" }, "Antworten der KI (vom Honeypot ausgeliefert, nichts ausgeführt)"), aiReplies(a.ai_replies)) : null,
    h("div", { class: "foot" },
      toggle,
      showIP ? h("a", { href: "#/attacker/" + encodeURIComponent(a.ip) }, "Angreifer-Profil und Bericht") : null,
      (a.sessions || []).length && (a.counts.command || a.counts.tty) ? h("a", { href: "#/session/" + encodeURIComponent(a.sessions[a.sessions.length - 1]) }, "Sitzung ansehen") : null),
    evBox);
  if (open && open.has(a.id)) setOpen(true);
  return el;
}

// Kompakte Zeile ("Gerade aktiv" im Dashboard)
export function attackRow(a, { fresh = false, open = null } = {}) {
  const detail = h("div", { class: "detail" });
  const row = h("div", { class: "row" + (fresh ? " fresh" : ""), style: { "--c": sevColor(a.stufe) }, tabindex: 0, role: "button", "aria-expanded": "false" },
    h("div", { class: "bar" }),
    h("div", { style: { minWidth: 0 } },
      h("div", { class: "ip" }, flag(a.country), h("span", { class: "mono" }, a.ip)),
      h("div", { class: "where" }, where(a))),
    h("div", { class: "when" }, h("span", { "data-rel": a.last }, relTime(a.last)), h("span", { class: "badge stufe" }, STUFE_KURZ[a.stufe])),
    h("div", { class: "sum" }, h("b", null, a.profile), " – ", summary(a)),
    h("div", { class: "chips" }, a.services.map((sv) => h("span", { class: "badge svc", style: { background: svcColor(sv) } }, svcName(sv))),
      counted(a.creds || [], 3).map((c) => h("span", { class: "chip mono", title: c }, c)),
      !a.creds?.length ? counted(a.paths || [], 2).map((c) => h("span", { class: "chip mono", title: c }, c)) : null),
    detail);
  let loaded = false;
  const toggle = async (ev) => {
    if (ev.target.closest("a")) return;
    const on = !row.classList.contains("open");
    row.classList.toggle("open", on);
    row.setAttribute("aria-expanded", String(on));
    if (open) on ? open.add(a.id) : open.delete(a.id);
    if (on && !loaded) {
      loaded = true;
      mount(detail, h("p", { class: "muted" }, "Lade …"));
      try {
        const d = await attackEvents(a);
        d.groups = d.groups.slice(-14);
        mount(detail, eventGroups(d).map((x) => x), h("div", { class: "links" },
          h("a", { href: "#/attacker/" + encodeURIComponent(a.ip) }, "Angreifer-Profil"), h("a", { href: "#/attacks?q=" + encodeURIComponent(a.ip) }, "Alle Angriffe dieser IP")));
        detail.querySelectorAll(".evrow").forEach((r) => r.classList.replace("evrow", "ev"));
      } catch (e) { mount(detail, h("div", { class: "msg err" }, e.message)); loaded = false; }
    }
  };
  row.addEventListener("click", toggle);
  row.addEventListener("keydown", (ev) => { if ((ev.key === "Enter" || ev.key === " ") && ev.target === row) { ev.preventDefault(); toggle(ev); } });
  if (open && open.has(a.id)) toggle({ target: row });
  return row;
}

// Live-Aktualisierung: IPs aus dem Live-Strom sammeln und alle 2 s deren aktuelle Angriffe holen.
export function liveAttacks(ctx, onUpdate) {
  const dirty = new Set();
  ctx.live((e) => { if (e.src_ip) dirty.add(e.src_ip); });
  ctx.every(2000, async () => {
    if (!dirty.size || document.hidden) return;
    const ips = [...dirty].slice(0, 50);
    ips.forEach((ip) => dirty.delete(ip));
    try {
      const d = await api("attacks?range=24h&limit=200&own=1&ip=" + ips.map(encodeURIComponent).join(","));
      // je IP nur der neueste Angriff hat sich geändert
      const seen = new Set(), latest = [];
      for (const a of d.attacks) if (!seen.has(a.ip)) { seen.add(a.ip); latest.push(a); }
      if (ctx.current()) onUpdate(latest);
    } catch { /* nächster Versuch */ }
  });
}

// ---------- Seite "Angriffe" ----------

export async function viewAttacks(el, ctx, query = "") {
  const params = new URLSearchParams(query.replace(/^\?/, ""));
  // Filter aus dem Link übernehmen (z. B. von den Kennzahlen im Dashboard)
  const f = {
    range: rangeOK(params.get("range")) ? params.get("range") : rangeOK(store("attRange")) ? store("attRange") : "24h",
    stufe: new Set((params.get("stufe") || "").split(",").filter((x) => /^[0-4]$/.test(x)).map(Number)),
    service: params.get("service") || "", q: params.get("q") || "", success: params.get("success") === "1", paused: false,
    ai: params.get("ki") === "1",
    own: params.get("own") === "1",
    // Dauer-Brute-Forcer ausblenden (hive/bruteforce.go); gemerkt im Browser
    hideBrute: params.has("brute") ? params.get("brute") === "0" : store("attHideBrute") === "1",
  };
  let nBrute = 0;
  let nOwn = 0;
  const open = new Set();
  let list = [], matched = 0, stufen = [0, 0, 0, 0, 0], truncated = false;
  const briefs = {}; // KI-Kurzanalysen je Angriff (hive/aiplus.go)

  const rangeSeg = rangePicker(f.range, RANGES, (v) => { f.range = v; store("attRange", v); load(); });
  const pauseBtn = h("button", { class: "btn", onclick: () => { f.paused = !f.paused; pauseBtn.textContent = f.paused ? "Fortsetzen" : "Pausieren"; if (!f.paused) load(); } }, "Pausieren");
  header("Angriffe", { extra: [viewSwitch("gruppen"), rangeSeg, pauseBtn] });

  let qTimer;
  const search = h("input", { type: "search", placeholder: "Suche: Text oder z. B. service:ssh stufe>=3 cmd:*wget* -scanner:ja", value: f.q, "aria-label": "Suche",
    style: { minWidth: "320px", flex: "1" },
    oninput: (e) => { clearTimeout(qTimer); qTimer = setTimeout(() => { f.q = e.target.value.trim(); load(); }, 350); } });
  // Gespeicherte Suchen (hive/query.go): Klick setzt die Suche, × löscht (nur Admin)
  const saved = h("div", { class: "filters" });
  const setQ = (q) => { search.value = q; f.q = q; load(); };
  const renderSaved = (list) => mount(saved, list.map((s) => h("span", { class: "fchip" + (f.q === s.q ? " on" : ""), title: s.q },
    h("a", { href: "#", onclick: (e) => { e.preventDefault(); setQ(s.q); renderSaved(list); } }, s.name),
    h("button", { class: "linklike", title: "Gespeicherte Suche löschen", "aria-label": "löschen", onclick: async () => {
      try { renderSaved(await api("searches/" + encodeURIComponent(s.name), { method: "DELETE" })); } catch { /* Leserolle */ }
    } }, "×"))),
    h("button", { class: "btn small", title: "Aktuelle Suche unter einem Namen speichern", onclick: async () => {
      if (!f.q) { alert("Erst etwas suchen, dann speichern."); return; }
      const name = prompt("Name für diese Suche:", "");
      if (!name) return;
      try { renderSaved(await api("searches", { method: "POST", body: { name, q: f.q } })); } catch (e) { alert(e.message); }
    } }, "Suche speichern"),
    h("details", { class: "aw-small" }, h("summary", null, "Suchsprache"),
      h("div", { class: "muted", style: { maxWidth: "640px" } },
        "Mehrere Teile müssen alle zutreffen, „-“ davor kehrt um, Anführungszeichen halten Wörter zusammen. Felder: ",
        h("code", null, "ip country asn org service port stufe events user pass cred cmd path url tag cve regel produkt client fp wallet art scanner login ki nachladen dauer"),
        ". Zahlen mit = < > <= >= (", h("code", null, "stufe>=3"), ", ", h("code", null, "port:5555"), "), Stufe auch als Wort (", h("code", null, "stufe:befehle"),
        "), * als Platzhalter (", h("code", null, "cmd:*xmrig*"), "), ", h("code", null, "scanner:ja"), " / ", h("code", null, "login:ja"), " / ", h("code", null, "ki:ja"), " (das Sprachmodell hat geantwortet) / ", h("code", null, "nachladen:ja"), " (wollte eine Datei nachladen) / ", h("code", null, "dauer:ja"), " (Dauer-Brute-Force).")));
  api("searches").then(renderSaved).catch(() => {});
  const chips = h("div", { class: "filters" });
  const info = h("div", { class: "muted", style: { fontSize: "12.5px" } });
  const feed = h("div", { class: "feed" });
  const more = h("button", { class: "btn", hidden: true, onclick: () => load(true) }, "Ältere laden");
  const nAct = h("div", { class: "big num" }, "–");
  const sideTop = h("ul", { class: "toplist heat" });

  function renderChips() {
    const chip = (on, label, n, color, click) => h("button", { class: "fchip" + (on ? " on" : ""), onclick: click, "aria-pressed": String(on) },
      color ? h("i", { style: { background: color } }) : null, label, n != null ? h("b", null, fmtNum(n)) : null);
    mount(chips,
      f.success ? chip(true, "Nur angenommene Logins ✕", null, sevColor(2), () => { f.success = false; load(); }) : null,
      STUFE.map((st, i) => chip(f.stufe.has(i), st, stufen[i], sevColor(i), () => { f.stufe.has(i) ? f.stufe.delete(i) : f.stufe.add(i); load(); })),
      h("span", { class: "fsep" }),
      ["ssh", "telnet", "http", "https", "mysql", "redis", "rdp", "vnc", "ftp", "smtp"].map((sv) => chip(f.service === sv, svcName(sv), null, svcColor(sv), () => { f.service = f.service === sv ? "" : sv; load(); })),
      h("span", { class: "fsep" }),
      chip(f.ai, "Beantwortet durch KI", null, "var(--s7)", () => { f.ai = !f.ai; load(); }),
      nBrute || f.hideBrute ? [h("span", { class: "fsep" }), h("span", { title: BRUTE_TITLE },
        chip(f.hideBrute, "Dauer-Brute-Force ausblenden", nBrute, null, () => { f.hideBrute = !f.hideBrute; store("attHideBrute", f.hideBrute ? "1" : "0"); load(); }))] : null,
      nOwn || f.own ? [h("span", { class: "fsep" }), chip(f.own, "Eigene Tests zeigen", nOwn, null, () => { f.own = !f.own; load(); })] : null);
  }
  function renderSide() {
    const now = Date.now();
    nAct.textContent = fmtNum(list.filter((a) => now - a.last < 15 * 60e3).length);
    const by = new Map();
    for (const a of list) if (a.country) by.set(a.country, (by.get(a.country) || 0) + 1);
    const top = [...by].sort((x, y) => y[1] - x[1]).slice(0, 6), max = top[0]?.[1] || 1;
    mount(sideTop, top.length ? top.map(([cc, n]) => h("li", null, h("span", { class: "k" }, flag(cc), " ", countryName(cc)), h("span", { class: "n" }, fmtNum(n)),
      h("span", { class: "bar" }, h("i", { style: { width: (n / max) * 100 + "%" } })))) : h("li", { class: "muted" }, "–"));
  }
  const seenCount = () => {
    // wievielter Angriff einer IP in der Liste (älteste zuerst gezählt)
    const by = new Map();
    for (const a of [...list].sort((x, y) => x.first - y.first)) { by.set(a.ip, (by.get(a.ip) || 0) + 1); a.seen = by.get(a.ip); }
  };
  const els = new Map(); // Angriff -> Element, damit Live-Updates nur die geänderte Karte ersetzen
  const setInfo = () => { info.textContent = `${fmtNum(list.length)} von ${fmtNum(matched)} Angriffen angezeigt` + (truncated ? " · sehr viele Daten: nur die neuesten 500.000 Ereignisse ausgewertet" : ""); };
  function render() {
    seenCount();
    renderChips();
    setInfo();
    els.clear();
    mount(feed, list.length ? list.map((a) => { const e = attackCard(a, { open, brief: briefs[a.id] }); els.set(a.id, e); return e; }) : h("div", { class: "card empty" }, "Keine Angriffe für diese Auswahl."));
    renderSide();
  }
  // Hält den Inhalt an der Stelle, die man gerade liest: Ist man heruntergescrollt, wird
  // nach dem Einfügen um die Höhenänderung oberhalb des Ankers nachgescrollt.
  function keepAnchor(change) {
    const cards = [...feed.children];
    const anchor = window.scrollY > feed.offsetTop ? cards.find((c) => c.getBoundingClientRect().bottom > 70) : null;
    const before = anchor ? anchor.getBoundingClientRect().top : 0;
    change();
    if (anchor && anchor.isConnected) {
      const diff = anchor.getBoundingClientRect().top - before;
      if (diff) window.scrollBy(0, diff);
    }
  }
  function upsert(a) {
    seenCount();
    const old = els.get(a.id), el = attackCard(a, { fresh: true, open, brief: briefs[a.id] });
    keepAnchor(() => {
      els.set(a.id, el);
      if (old) old.remove();
      if (!list.length || feed.querySelector(".empty")) feed.replaceChildren();
      feed.prepend(el);
    });
  }
  const qs = (before) => {
    const p = new URLSearchParams({ range: f.range, limit: "40" });
    if (f.stufe.size) p.set("stufe", [...f.stufe].join(","));
    if (f.service) p.set("service", f.service);
    if (f.success) p.set("success", "1");
    if (f.own) p.set("own", "1");
    if (f.hideBrute) p.set("brute", "0");
    const q = [f.q, f.ai ? "ki:ja" : ""].filter(Boolean).join(" ");
    if (q) p.set("q", q);
    if (before) p.set("before", String(before));
    return p.toString();
  };
  async function load(older = false) {
    const d = await api("attacks?" + qs(older && list.length ? list[list.length - 1].last : 0));
    if (!ctx.current()) return;
    list = older ? [...list, ...d.attacks] : d.attacks;
    matched = d.matched; stufen = d.stufen; truncated = d.truncated; nOwn = d.own || 0; nBrute = d.brute || 0;
    more.hidden = list.length >= matched;
    render();
    fillBriefs(d.attacks);
  }
  // Kurzanalysen nachladen und nur die betroffenen Karten ersetzen
  async function fillBriefs(items) {
    const ids = items.filter((a) => (a.stufe >= 3 || (a.tags || []).length) && !briefs[a.id]).map((a) => a.id);
    if (!ids.length) return;
    const got = await loadBriefs(ids);
    if (!ctx.current()) return;
    for (const [id, b] of Object.entries(got)) {
      briefs[id] = b;
      const a = list.find((x) => x.id === id), old = els.get(id);
      if (!a || !old) continue;
      const el = attackCard(a, { open, brief: b });
      old.replaceWith(el);
      els.set(id, el);
    }
  }

  mount(el, h("div", { class: "angriffe" },
    h("div", { class: "stack" },
      h("div", { class: "filters" }, search, info),
      aiSearch((q, range) => { location.hash = "#/attacks?" + new URLSearchParams({ range, q }); }, RANGES), // Suche in Alltagssprache (hive/aiplus.go)
      saved, chips, feed, more),
    h("aside", { class: "side" },
      card("Gerade aktiv", nAct, h("div", { class: "note-box" }, "Angreifer mit Aktivität in den letzten 15 Minuten")),
      card("Herkunft (angezeigte Angriffe)", sideTop),
      card("So ist die Liste aufgebaut", h("div", { class: "note-box" },
        "Alle Ereignisse einer IP gehören zu einem Angriff, solange zwischen ihnen weniger als 15 Minuten liegen. ",
        "Die Farbe zeigt, wie weit der Angreifer kam: ",
        STUFE.map((s, i) => [h("span", { style: { color: sevColor(i), fontWeight: 600 } }, s), i < 4 ? " → " : ""]),
        ". Die Art (z. B. „SSH-Brute-Force“) ist aus dem Verhalten geschätzt.")))));
  await load();

  const matchesFilter = (a) => (!f.stufe.size || f.stufe.has(a.stufe)) && (!f.service || a.services.includes(f.service)) && (!f.success || a.success) && (!f.ai || (a.ai_replies || []).length > 0) && (!f.hideBrute || !a.brute) && !f.q;
  liveAttacks(ctx, (updated) => {
    if (f.paused) return;
    if (!f.own) updated = updated.filter((a) => !a.own);
    for (const a of updated.sort((x, y) => x.last - y.last)) {
      const i = list.findIndex((x) => x.id === a.id);
      if (i < 0 && !matchesFilter(a)) continue;
      if (i >= 0) list.splice(i, 1); else matched++;
      list.unshift(a);
      upsert(a);
    }
    setInfo();
  });
  ctx.every(30000, () => { if (!f.paused && !document.hidden) renderSide(); });
}

// Umschalter der Seite "Angriffe": gebündelt, einzelne Ereignisse, Sitzungen (drei Routen)
export function viewSwitch(cur) {
  return h("div", { class: "seg", role: "group", "aria-label": "Ansicht" },
    [["gruppen", "#/attacks", "Gebündelt"], ["einzeln", "#/feed", "Einzelne Ereignisse"], ["sitzungen", "#/sessions", "Sitzungen"]].map(([k, href, label]) =>
      h("button", { class: cur === k ? "on" : "", "aria-pressed": String(cur === k), onclick: () => { location.hash = href; } }, label)));
}

