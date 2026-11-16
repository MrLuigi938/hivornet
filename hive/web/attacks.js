// Angriffe statt Ereignisse: Ereignisse einer IP werden zu Angriffen gebündelt
// (Lücke unter 15 Minuten, siehe hive/attacks.go). Karte je Angriff mit Stufe,
// vermuteter Art, Zusammenfassung und Zeitstreifen; kompakte Zeile fürs Dashboard.
import { h, mount, api, fmtNum, fmtTime, fmtDur, toMs, relTime, flag, store } from "./dom.js";
import { svcName, svcColor, countryName } from "./charts.js";
import { header, card, TYPE_NAME } from "./app.js";

export const STUFE = ["Abtasten", "Versuche", "Login angenommen", "Befehle ausgeführt", "Datei nachgeladen"];
export const STUFE_KURZ = ["Scan", "Versuche", "Login ok", "Befehle", "Download"];
export const sevColor = (n) => `var(--sev${n})`;
const TYPCOL = { connect: "var(--other)", client_version: "var(--other)", tls: "var(--other)", fingerprint: "var(--other)",
  login: "var(--sev1)", request: "var(--s2)", payload: "var(--s7)", command: "var(--sev3)", download: "var(--sev4)", tty: "var(--sev3)" };
const RANGES = [["1h", "1 Std"], ["24h", "24 Std"], ["7d", "7 Tage"], ["30d", "30 Tage"], ["90d", "90 Tage"], ["all", "Alles"]];

// Kurzfassung in einer Zeile
export function summary(a) {
  const c = a.counts || {}, p = [];
  if (c.login) p.push(`${fmtNum(c.login)} Login-Versuch${c.login > 1 ? "e" : ""}`);
  if (a.success) p.push("Login angenommen");
  if (c.request) p.push(`${fmtNum(c.request)} Web-Anfrage${c.request > 1 ? "n" : ""}`);
  if (c.payload) p.push(`${fmtNum(c.payload)}× Daten`);
  if (c.command) p.push(`${fmtNum(c.command)} Befehl${c.command > 1 ? "e" : ""}`);
  if (c.download) p.push(`${fmtNum(c.download)} Download${c.download > 1 ? "s" : ""}`);
  if (!p.length) p.push(a.ports.length > 1 ? `${a.ports.length} Ports abgetastet` : `Verbindung zu Port ${a.ports[0] || "?"}`);
  return p.join(" · ");
}

const where = (a) => [a.country ? [a.city, a.country_name || countryName(a.country)].filter(Boolean).join(", ") : "Herkunft unbekannt", a.asn ? `AS${a.asn} ${a.as_org || ""}`.trim() : ""].filter(Boolean).join(" · ");
const svcBadges = (a) => a.services.map((sv) => h("span", { class: "badge svc", style: { background: svcColor(sv) } }, svcName(sv)));
const counted = (list, max) => list.slice(0, max).map((x) => (x.n > 1 ? `${x.key} ×${fmtNum(x.n)}` : x.key));

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

// Große Karte (Seite "Angriffe", Angreifer-Profil)
export function attackCard(a, { fresh = false, open = null, showIP = true } = {}) {
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
    a.paths && a.paths.length ? ["Aufgerufene Pfade" + (a.paths_distinct > 1 ? ` (${fmtNum(a.paths_distinct)})` : ""), counted(a.paths, 8), a.paths_distinct > 8 ? `+${fmtNum(a.paths_distinct - 8)}` : null] : null,
    a.commands && a.commands.length ? ["Befehle", a.commands.slice(0, 6), a.commands.length > 6 ? `+${a.commands.length - 6}` : null] : null,
    a.urls && a.urls.length ? ["Nachlade-Adressen (nicht aufrufen)", a.urls, null, "hot"] : null,
    a.decoded && a.decoded.length ? ["Entschlüsselt (Base64, Hex …)", a.decoded, null, "decoded"] : null,
    a.tags && a.tags.length ? ["Erkannte Muster", a.tags.map((t) => t.label || t.key), null, "tag"] : null,
    a.clients && a.clients.length ? ["Client", a.clients, null] : null,
  ].filter(Boolean);
  const el = h("article", { class: "atk" + (fresh ? " fresh" : ""), style: { "--c": sevColor(a.stufe) } },
    h("div", { class: "l1" },
      showIP ? [flag(a.country), h("a", { class: "ip mono", href: "#/attacker/" + encodeURIComponent(a.ip) }, a.ip), h("span", { class: "where" }, where(a))] : null,
      h("div", { class: "right" },
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
    facts.length ? h("div", { class: "facts", style: a.strip && a.strip.length > 1 ? null : { marginTop: "12px" } }, facts.map(([k, items, more, cls]) => h("div", { class: "fact" },
      h("div", { class: "k" }, k),
      h("div", { class: "v" }, items.map((x) => h("span", { class: "pill mono" + (cls ? " " + cls : ""), title: x }, x)), more ? h("span", { class: "muted" }, more) : null)))) : null,
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
      const d = await api("attacks?range=24h&limit=200&ip=" + ips.map(encodeURIComponent).join(","));
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
    range: RANGES.some(([v]) => v === params.get("range")) ? params.get("range") : store("attRange") || "24h",
    stufe: new Set((params.get("stufe") || "").split(",").filter((x) => /^[0-4]$/.test(x)).map(Number)),
    service: params.get("service") || "", q: params.get("q") || "", success: params.get("success") === "1", paused: false,
  };
  const open = new Set();
  let list = [], matched = 0, stufen = [0, 0, 0, 0, 0], truncated = false;

  const rangeSeg = h("div", { class: "seg", role: "group", "aria-label": "Zeitraum" }, RANGES.map(([v, l]) => h("button", {
    class: f.range === v ? "on" : "", onclick: (ev) => { f.range = v; store("attRange", v); rangeSeg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b === ev.target)); load(); },
  }, l)));
  const pauseBtn = h("button", { class: "btn", onclick: () => { f.paused = !f.paused; pauseBtn.textContent = f.paused ? "Fortsetzen" : "Pausieren"; if (!f.paused) load(); } }, "Pausieren");
  header("Angriffe", { extra: [viewSwitch("gruppen"), rangeSeg, pauseBtn] });

  let qTimer;
  const search = h("input", { type: "search", placeholder: "Suche: IP, Land, Passwort, Befehl, Pfad …", value: f.q, "aria-label": "Suche",
    oninput: (e) => { clearTimeout(qTimer); qTimer = setTimeout(() => { f.q = e.target.value.trim(); load(); }, 350); } });
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
      ["ssh", "telnet", "http", "https", "mysql", "redis", "rdp", "vnc", "ftp", "smtp"].map((sv) => chip(f.service === sv, svcName(sv), null, svcColor(sv), () => { f.service = f.service === sv ? "" : sv; load(); })));
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
    mount(feed, list.length ? list.map((a) => { const e = attackCard(a, { open }); els.set(a.id, e); return e; }) : h("div", { class: "card empty" }, "Keine Angriffe für diese Auswahl."));
    renderSide();
  }
  function upsert(a) {
    seenCount();
    const old = els.get(a.id), el = attackCard(a, { fresh: true, open });
    els.set(a.id, el);
    if (old) old.remove();
    if (!list.length || feed.querySelector(".empty")) feed.replaceChildren();
    feed.prepend(el);
  }
  const qs = (before) => {
    const p = new URLSearchParams({ range: f.range, limit: "40" });
    if (f.stufe.size) p.set("stufe", [...f.stufe].join(","));
    if (f.service) p.set("service", f.service);
    if (f.success) p.set("success", "1");
    if (f.q) p.set("q", f.q);
    if (before) p.set("before", String(before));
    return p.toString();
  };
  async function load(older = false) {
    const d = await api("attacks?" + qs(older && list.length ? list[list.length - 1].last : 0));
    if (!ctx.current()) return;
    list = older ? [...list, ...d.attacks] : d.attacks;
    matched = d.matched; stufen = d.stufen; truncated = d.truncated;
    more.hidden = list.length >= matched;
    render();
  }

  mount(el, h("div", { class: "angriffe" },
    h("div", { class: "stack" },
      h("div", { class: "filters" }, search, info),
      chips, feed, more),
    h("aside", { class: "side" },
      card("Gerade aktiv", nAct, h("div", { class: "note-box" }, "Angreifer mit Aktivität in den letzten 15 Minuten")),
      card("Herkunft (angezeigte Angriffe)", sideTop),
      card("So ist die Liste aufgebaut", h("div", { class: "note-box" },
        "Alle Ereignisse einer IP gehören zu einem Angriff, solange zwischen ihnen weniger als 15 Minuten liegen. ",
        "Die Farbe zeigt, wie weit der Angreifer kam: ",
        STUFE.map((s, i) => [h("span", { style: { color: sevColor(i), fontWeight: 600 } }, s), i < 4 ? " → " : ""]),
        ". Die Art (z. B. „SSH-Brute-Force“) ist aus dem Verhalten geschätzt.")))));
  await load();

  const matchesFilter = (a) => (!f.stufe.size || f.stufe.has(a.stufe)) && (!f.service || a.services.includes(f.service)) && (!f.success || a.success) && !f.q;
  liveAttacks(ctx, (updated) => {
    if (f.paused) return;
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

