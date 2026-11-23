// Tab „Funde“ (hive/funde.go): Weg der Nachlade-Adressen vom Befehl bis zur Meldung,
// Stand je Anbieter, Fundbuch und Fallakte einer Datei mit Prüfprotokoll.
//
// Wie überall: Angreiferdaten nur als Text (h() aus dom.js); Adressen der Angreifer werden nie
// zu Links gemacht. Dateien gibt die Web-UI nie heraus, Skripte erscheinen nur als Text.
import { h, mount, api, fmtNum, fmtBytes, fmtDateTime, relTime } from "./dom.js";
import { state, header, cc } from "./app.js";

const PROV = {
  abuseipdb: ["AbuseIPDB", "var(--s2)"], urlhaus: ["URLhaus", "var(--s5)"], bazaar: ["MalwareBazaar", "var(--s7)"],
  dshield: ["DShield", "var(--s3)"], sample: ["Dateien sammeln", "var(--s4)"],
};
// Stand einer Meldung: [Text, Klasse]
const ST = {
  ok: ["angenommen", "ok"], known: ["schon bekannt", "known"], error: ["Fehler", "err"], wait: ["wartet", "wait"],
  dry: ["Probe", "dry"], skipped: ["nicht gemeldet", "dry"], "": ["–", "none"],
};
const stBadge = (s, text) => { const [t, c] = ST[s] || [s, "dry"]; return h("span", { class: "fd-st " + c }, h("i"), text || t); };
const KIND = { ip: "IP-Adresse", url: "Adresse", wallet: "Wallet", pool: "Mining-Pool" };

// Zustand der Ansicht (bleibt beim Neuladen der Daten erhalten)
const V = { tab: "files", q: "", filter: "", sel: "", sub: "inhalt" };

export async function viewFunde(el, ctx, query) {
  const p = new URLSearchParams(query || "");
  if (p.get("f")) { V.sel = p.get("f"); V.tab = "files"; }
  if (p.get("t")) V.tab = p.get("t");
  header("Funde", { range: true });
  const rng = /^(\d+)([hdwm])$/.test(state.range) ? state.range : "7d";
  const d = await api("funde?range=" + encodeURIComponent(rng));
  const cut = d.range_ms < ({ h: 36e5, d: 864e5, w: 6048e5, m: 2592e6 }[rng.slice(-1)] * Number(rng.slice(0, -1)));

  const reg = h("section", { class: "card" });
  const akte = h("section", { class: "card fd-akte", id: "fd-akte" });
  const renderReg = () => mount(reg, register(d, renderReg, openFile));
  function openFile(sha, sub) {
    V.sel = sha;
    V.sub = sub || "inhalt";
    V.tab = "files";
    history.replaceState(null, "", "#/funde?f=" + sha);
    renderReg();
    fileCase(akte, sha, ctx);
    akte.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  renderReg();
  mount(el, h("div", { class: "stack" },
    h("p", { class: "sub" }, "Was Angreifer nachladen wollten, was der Hive davon geholt hat und was an wen gemeldet wurde oder würde. ",
      "Ein Klick auf eine Datei öffnet ihre Fallakte mit Inhalt, Nachlade-Stufen, Verknüpfungen und dem genauen Wortlaut jeder Meldung.",
      cut ? h("span", { class: "muted" }, " Gezeigt werden höchstens die letzten 30 Tage.") : null),
    funnel(d, (tab, filter) => { V.tab = tab; V.filter = filter; renderReg(); reg.scrollIntoView({ behavior: "smooth", block: "start" }); }),
    providers(d),
    reg,
    akte));
  if (V.sel) fileCase(akte, V.sel, ctx);
  else akte.hidden = true;
}

// ---------- Trichter ----------
function funnel(d, go) {
  const f = d.funnel, reasons = Object.entries(d.skip_reasons || {}).sort((a, b) => b[1] - a[1]);
  const reported = (f.urlhaus_ok || 0) + (f.urlhaus_error || 0);
  const steps = [
    ["Nachlade-Adressen", f.seen || 0, "in Befehlen und Downloads", "urls", ""],
    ["zulässig", f.allowed || 0, reasons.length ? `${fmtNum((f.seen || 0) - (f.allowed || 0))} verworfen: ${reasons.slice(0, 2).map(([w]) => w.replace(/^Adresse nicht zulässig: /, "")).join(", ")}` : "nichts verworfen", "skip", ""],
    ["geholt", f.fetched || 0, [f.fetch_error ? `${fmtNum(f.fetch_error)} Fehler` : "", f.not_tried ? `${fmtNum(f.not_tried)} nicht versucht` : ""].filter(Boolean).join(" · ") || (f.allowed ? "alle versucht" : "–"), "urls", "fetched"],
    ["Schadsoftware", f.malware || 0, f.fetched ? `${fmtNum((f.fetched || 0) - (f.malware || 0))} harmlos oder unklar` : "–", "urls", "malware"],
    ["an URLhaus", reported, [f.urlhaus_wait ? `${fmtNum(f.urlhaus_wait)} wartet` : "", f.urlhaus_dry ? `${fmtNum(f.urlhaus_dry)} Probe` : ""].filter(Boolean).join(" · ") || "gesendet", "urls", "reported"],
    ["angenommen", f.urlhaus_ok || 0, f.urlhaus_error ? `${fmtNum(f.urlhaus_error)} abgelehnt` : "keine Ablehnung", "urls", f.urlhaus_error ? "rejected" : "accepted"],
  ];
  const top = Math.max(1, steps[0][1]);
  return h("div", { class: "fd-funnel", role: "list" }, steps.map(([l, v, hint, tab, filter], i) => h("button", {
    type: "button", role: "listitem", class: i === 5 && f.urlhaus_error ? "alarm" : "", onclick: () => go(tab, filter),
    title: "Zeigt die passenden Einträge im Fundbuch",
  }, h("span", { class: "l" }, l), h("span", { class: "v num" }, fmtNum(v)), h("span", { class: "h" }, hint),
  h("span", { class: "bar" }, h("i", { style: { width: Math.round((100 * v) / top) + "%" } })))));
}

// ---------- Anbieter ----------
function providers(d) {
  const row = (p) => {
    const c = p.counts || {}, [name, col] = PROV[p.kind];
    const sent = Object.values(c).reduce((a, b) => a + b, 0);
    const mode = !p.enabled ? h("span", { class: "chip", title: p.disabled ? "aus: " + p.disabled : "in den Einstellungen ausgeschaltet" }, "aus") : p.dry_run ? h("span", { class: "chip" }, "Probemodus") : h("span", { class: "chip ok" }, "aktiv");
    const note = !p.enabled && p.disabled ? "aus: " + p.disabled : p.pause_until ? "pausiert bis " + new Date(p.pause_until).toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" })
      : p.last_error || (p.last_run ? "zuletzt geprüft " + relTime(p.last_run) : "");
    const maxDay = Math.max(1, ...p.days);
    return h("tr", null,
      h("td", null, h("span", { class: "fd-name", style: { "--c": col } }, h("i"), name)),
      h("td", null, mode),
      h("td", { class: "num" }, fmtNum(sent)),
      h("td", null, c.ok ? stBadge("ok", fmtNum(c.ok)) : h("span", { class: "muted" }, "0")),
      h("td", null, c.known ? stBadge("known", fmtNum(c.known)) : h("span", { class: "muted" }, "–")),
      h("td", null, c.error ? stBadge("error", fmtNum(c.error)) : h("span", { class: "muted" }, "0")),
      h("td", null, p.waiting ? stBadge("wait", fmtNum(p.waiting)) : h("span", { class: "muted" }, "0")),
      h("td", null, c.dry ? stBadge("dry", fmtNum(c.dry)) : c.skipped ? stBadge("skipped", fmtNum(c.skipped)) : h("span", { class: "muted" }, "–")),
      h("td", { class: "muted" }, p.quota || "–"),
      h("td", { class: p.last_error || p.pause_until ? "fd-errtext" : "muted", title: note }, note),
      h("td", null, h("span", { class: "fd-spark", title: "Erfolge je Tag, letzte 7 Tage: " + p.days.join(", ") }, p.days.map((v) => h("i", { style: { height: 2 + Math.round((v / maxDay) * 18) + "px" } })))));
  };
  return h("section", { class: "card" },
    h("div", { class: "head" }, h("h2", null, "Anbieter"), h("div", { class: "grow" }),
      h("span", { class: "hint" }, d.delay_min ? `Meldungen erst nach ${d.delay_min} Minuten Ruhe · ` : "Meldungen ohne Verzögerung · "),
      h("a", { class: "hint", href: "#/settings/weitergabe" }, "Einstellungen")),
    h("div", { class: "tablewrap" }, h("table", { class: "fd-prov" },
      h("thead", null, h("tr", null, ["Anbieter", "Modus", "Einträge", "angenommen", "schon bekannt", "Fehler", "wartet", "Probe / ausgelassen", "Kontingent", "Hinweis", "7 Tage"].map((t) => h("th", null, t)))),
      h("tbody", null, d.providers.map(row)))));
}

// ---------- Fundbuch ----------
function register(d, rerender, openFile) {
  const tabs = [["files", "Dateien", d.files.length], ["urls", "Nachlade-Adressen", d.urls.length], ["attackers", "Angreifer", d.attackers.length],
    ["infra", "Infrastruktur", d.infra.length], ["ai", "KI-Antworten an Angreifer", d.ai.length], ["skip", "Nicht geholt", d.skipped.length + (d.fetch_skips || []).length]];
  const filters = {
    files: [["", "Alle"], ["malware", "nur Schadsoftware"], ["open", "Meldung offen"], ["error", "Fehler"]],
    urls: [["", "Alle"], ["fetched", "geholt"], ["malware", "Schadsoftware"], ["reported", "an URLhaus"], ["accepted", "angenommen"], ["rejected", "abgelehnt"], ["wait", "wartet"]],
    attackers: [["", "Alle"], ["files", "mit Datei"], ["open", "nicht gemeldet"]],
  }[V.tab] || [];
  const body = h("div", { class: "tablewrap" });
  const search = h("input", { type: "search", placeholder: "Filtern: Adresse, Hash, IP, Typ …", value: V.q, "aria-label": "Fundbuch filtern",
    oninput: (e) => { V.q = e.target.value.trim().toLowerCase(); mount(body, regTable(d, openFile)); } });
  mount(body, regTable(d, openFile));
  return [
    h("div", { class: "fd-tabs", role: "tablist" }, tabs.map(([k, l, n]) => h("button", { type: "button", role: "tab", "aria-selected": String(V.tab === k), class: V.tab === k ? "on" : "",
      onclick: () => { V.tab = k; V.filter = ""; rerender(); } }, l, h("span", { class: "n" }, fmtNum(n))))),
    h("div", { class: "fd-tools" }, search, filters.map(([k, l]) => h("button", { type: "button", class: "fchip" + (V.filter === k ? " on" : ""), onclick: () => { V.filter = k; rerender(); } }, l))),
    body,
  ];
}

const hit = (...parts) => !V.q || parts.join(" ").toLowerCase().includes(V.q);
const shortSha = (s) => (s ? s.slice(0, 12) + "…" + s.slice(-6) : "");
const ago = (t) => (t ? relTime(t) : "–");

function regTable(d, openFile) {
  let head = [], rows = [];
  const empty = (t) => h("tr", null, h("td", { colspan: head.length, class: "empty" }, t));
  if (V.tab === "files") {
    head = ["Datei", "Typ", "Größe", "Muster", "Ziele", "Quellen", "Angreifer", "Zuletzt", "URLhaus", "MalwareBazaar"];
    rows = d.files.filter((f) => hit(f.sha256, f.name, f.type, f.arch, f.patterns.join(" "), f.sources.join(" ")))
      .filter((f) => V.filter === "malware" ? f.malware : V.filter === "open" ? f.malware && !f.urlhaus : V.filter === "error" ? f.urlhaus === "error" || f.bazaar === "error" : true)
      .map((f) => h("tr", { class: "click" + (V.sel === f.sha256 ? " sel" : ""), tabindex: 0, onclick: () => openFile(f.sha256), onkeydown: (e) => { if (e.key === "Enter") openFile(f.sha256); } },
        h("td", null, h("div", { class: "fd-strong" }, f.name || "(ohne Namen)"), h("div", { class: "fd-hash" }, shortSha(f.sha256))),
        h("td", null, f.missing ? h("span", { class: "muted" }, f.missing) : [f.type || "–", h("div", { class: "muted small" }, [f.arch, f.bits ? f.bits + " Bit" : "", f.packed, f.static ? "statisch" : ""].filter(Boolean).join(" · "))]),
        h("td", { class: "num" }, f.size ? fmtBytes(f.size) : "–"),
        h("td", null, f.patterns.length ? f.patterns.slice(0, 3).map((p) => h("span", { class: "chip" }, p)) : h("span", { class: "muted" }, "–")),
        h("td", { class: "num" }, f.iocs || "–"), h("td", { class: "num" }, f.sources.length), h("td", { class: "num" }, f.ips.length),
        h("td", { class: "muted" }, ago(f.last)), h("td", null, stBadge(f.urlhaus || "")), h("td", null, stBadge(f.bazaar || ""))));
    if (!rows.length) rows = [empty(d.files.length ? "Nichts passt zum Filter." : "Im Zeitraum keine Dateien. Cowrie-Downloads und mit „Dateien sammeln“ geholte Dateien erscheinen hier.")];
  } else if (V.tab === "urls") {
    head = ["Adresse", "Benutzt", "Angreifer", "Geholt", "Datei", "URLhaus", "Erstmals", "Zuletzt"];
    const flt = {
      fetched: (u) => u.fetch === "ok", malware: (u) => u.malware, reported: (u) => u.urlhaus === "ok" || u.urlhaus === "error",
      accepted: (u) => u.urlhaus === "ok", rejected: (u) => u.urlhaus === "error", wait: (u) => u.urlhaus === "wait",
    }[V.filter] || (() => true);
    rows = d.urls.filter(flt).filter((u) => hit(u.url, u.sha256, u.ips.join(" "))).map((u) => h("tr", { class: u.sha256 ? "click" : "", onclick: u.sha256 ? () => openFile(u.sha256) : null },
      h("td", { class: "mono wrap" }, u.url, h("div", { class: "muted small" }, u.services.join(", "))),
      h("td", { class: "num" }, fmtNum(u.uses) + "×"),
      h("td", null, u.ips.slice(0, 2).map((ip) => h("div", null, h("a", { class: "mono", href: "#/attacker/" + encodeURIComponent(ip), onclick: (e) => e.stopPropagation() }, ip))), u.n_ips > 2 ? h("span", { class: "muted small" }, `+${u.n_ips - 2}`) : null),
      h("td", null, u.fetch === "ok" ? stBadge("ok", "geholt") : u.fetch === "error" ? stBadge("error", u.fetch_error || "Fehler") : h("span", { class: "muted" }, "nicht versucht")),
      h("td", null, u.sha256 ? [h("span", { class: "fd-hash" }, shortSha(u.sha256)), u.malware ? h("div", null, h("span", { class: "chip warn" }, "Schadsoftware")) : null] : h("span", { class: "muted" }, "–")),
      h("td", { title: u.note || "" }, stBadge(u.urlhaus || "", u.urlhaus === "wait" ? u.note : undefined)),
      h("td", { class: "muted" }, fmtDateTime(u.first)), h("td", { class: "muted" }, ago(u.last))));
    if (!rows.length) rows = [empty("Keine Nachlade-Adressen in diesem Filter.")];
  } else if (V.tab === "attackers") {
    head = ["Angreifer", "Herkunft", "Adressen", "Dateien", "AbuseIPDB", "Erstmals", "Zuletzt"];
    rows = d.attackers.filter((a) => hit(a.ip, a.as_org, a.country)).filter((a) => V.filter === "files" ? a.files : V.filter === "open" ? !a.abuse || a.abuse === "dry" : true)
      .map((a) => h("tr", null,
        h("td", null, h("a", { class: "mono", href: "#/attacker/" + encodeURIComponent(a.ip) }, a.ip)),
        h("td", null, cc(a.country), " ", h("span", { class: "muted" }, a.as_org || "")),
        h("td", { class: "num" }, a.urls), h("td", { class: "num" }, a.files || "–"),
        h("td", { title: a.note || "" }, stBadge(a.abuse || "", a.abuse === "ok" ? "gemeldet" : a.abuse === "dry" ? "würde melden" : a.abuse === "wait" ? a.note : undefined)),
        h("td", { class: "muted" }, fmtDateTime(a.first)), h("td", { class: "muted" }, ago(a.last))));
    if (!rows.length) rows = [empty("Keine Angreifer mit Nachlade-Adressen im Zeitraum.")];
  } else if (V.tab === "infra") {
    head = ["Art", "Wert", "In Dateien", ""];
    const byName = Object.fromEntries(d.files.map((f) => [f.sha256, f]));
    rows = d.infra.filter((x) => hit(x.value, x.kind)).map((x) => h("tr", null,
      h("td", null, h("span", { class: "chip" }, KIND[x.kind] || x.kind)),
      h("td", { class: "mono wrap" }, x.value),
      h("td", null, x.files.slice(0, 4).map((s) => h("button", { type: "button", class: "btn small", onclick: () => openFile(s, "ziele") }, (byName[s] && byName[s].name) || shortSha(s)))),
      h("td", null, h("a", { class: "small", href: attSearch(x.value), title: "Sucht über den ganzen gespeicherten Zeitraum in Befehlen, Adressen und entschlüsselten Inhalten" }, "In Angriffen suchen"))));
    if (!rows.length) rows = [empty("In den untersuchten Dateien stehen keine Adressen, Pools oder Wallets.")];
    rows.unshift(h("tr", null, h("td", { colspan: 4, class: "muted small" }, "Ziele, die in den Dateien stehen (Steuerserver, weitere Adressen, Mining-Pools, Wallets). Sie werden nie aufgerufen und nie gemeldet.")));
  } else if (V.tab === "ai") {
    head = ["Zeit", "Angreifer", "Art", "Eingabe des Angreifers", "Antwort an den Angreifer"];
    rows = d.ai.filter((x) => hit(x.ip, x.input, x.output)).map((x) => h("tr", null,
      h("td", { class: "muted num" }, fmtDateTime(x.t)),
      h("td", null, h("a", { class: "mono", href: "#/attacker/" + encodeURIComponent(x.ip) }, x.ip)),
      h("td", null, x.kind === "web" ? "Web" : "Shell", x.cached ? h("div", { class: "muted small" }, "aus dem Speicher") : null),
      h("td", { class: "mono wrap" }, x.input),
      h("td", null, outCell(x.output))));
    if (!rows.length) rows = [empty("Im Zeitraum keine Antworten des Sprachmodells an Angreifer (Einstellungen → Auswertung und KI → Sprachmodell-Antworten).")];
  } else if (V.tab === "skip") {
    head = ["Adresse", "Grund", "Benutzt", "Angreifer", "Zuletzt"];
    rows = d.skipped.filter((u) => hit(u.url, u.why)).map((u) => h("tr", null,
      h("td", { class: "mono wrap" }, u.url), h("td", null, u.why), h("td", { class: "num" }, fmtNum(u.uses) + "×"),
      h("td", null, u.ips.slice(0, 2).map((ip) => h("div", null, h("a", { class: "mono", href: "#/attacker/" + encodeURIComponent(ip) }, ip)))),
      h("td", { class: "muted" }, ago(u.last))));
    for (const s of d.fetch_skips || []) {
      if (hit(s.url, s.reason)) rows.push(h("tr", null, h("td", { class: "mono wrap" }, s.url), h("td", null, s.reason), h("td", { class: "muted" }, "–"), h("td", { class: "muted" }, "–"), h("td", { class: "muted" }, ago(s.time))));
    }
    if (!rows.length) rows = [empty("Nichts verworfen.")];
  }
  return h("table", { class: "fd-reg" }, h("thead", null, h("tr", null, head.map((t) => h("th", null, t)))), h("tbody", null, rows));
}

// Link zur Seite Angriffe: über alles Gespeicherte (sonst gilt der zuletzt gewählte Zeitraum,
// oft 24 Stunden, und ältere Funde liefern nichts); in Anführungszeichen als ein Suchbegriff.
const attSearch = (v) => "#/attacks?range=all&q=" + encodeURIComponent('"' + String(v).replace(/"/g, "") + '"');

// Antwort des Sprachmodells: drei Zeilen als Vorschau, umgebrochen; Klick zeigt alles.
function outCell(text) {
  const t = String(text || "");
  if (!t) return h("span", { class: "muted" }, "leer (404 vom Server)");
  const box = h("div", { class: "fd-out", title: "Klicken zeigt die ganze Antwort" }, t);
  const long = t.length > 220 || t.split("\n").length > 4;
  if (!long) { box.classList.add("open"); return box; }
  const more = h("button", { type: "button", class: "linklike small" }, "ganz zeigen");
  const toggle = () => { const on = box.classList.toggle("open"); more.textContent = on ? "einklappen" : "ganz zeigen"; };
  box.addEventListener("click", toggle);
  more.addEventListener("click", toggle);
  return h("div", null, box, more);
}

// ---------- Fallakte ----------
async function fileCase(box, sha, ctx) {
  box.hidden = false;
  mount(box, h("p", { class: "muted" }, "Lade Fallakte …"));
  let d;
  try { d = await api("funde/file?sha=" + encodeURIComponent(sha)); } catch (e) { mount(box, h("div", { class: "msg err" }, e.message)); return; }
  if (!ctx.current()) return;
  const f = d.file, si = d.info;
  const subs = [["inhalt", "Inhalt"], ["stufen", d.stages.length ? `Nachlade-Stufen (${d.stages.length})` : "Herkunft"], ["ziele", "Eingebettete Ziele"],
    ["netz", "Verknüpfungen"], ["protokoll", `Prüfprotokoll (${d.audit.length})`], ["extern", "Externe Daten"], ["ki", `KI-Antworten (${d.ai.length})`]];
  const body = h("div");
  const nav = h("div", { class: "fd-subtabs", role: "tablist" });
  const show = (k) => {
    V.sub = k;
    mount(nav, subs.map(([s, l]) => h("button", { type: "button", role: "tab", "aria-selected": String(s === k), class: s === k ? "on" : "", onclick: () => show(s) }, l)));
    mount(body, caseBody(k, d));
  };
  const facts = [
    ["SHA-256", h("span", { class: "fd-hash" }, sha)], ["Typ", si ? si.type : f.missing || "–"], ["Plattform", si && si.arch ? [si.arch, si.bits ? si.bits + " Bit" : "", si.endian].filter(Boolean).join(" · ") : "–"],
    ["Größe", si ? fmtNum(si.size) + " Byte" : "–"], ["Gepackt", si && si.packed ? si.packed : "nicht erkannt"], ["Erstmals", f.first ? fmtDateTime(f.first) : "–"],
    ["Zuletzt", ago(f.last)], ["Sitzungen", f.sessions || "–"], ["Angreifer", f.ips.length], ["Quellen", f.sources.length],
  ];
  mount(box,
    h("div", { class: "fd-title" }, h("span", { class: "fd-kicker" }, "Fallakte · Datei"), h("h2", null, f.name || shortSha(sha)),
      f.malware ? h("span", { class: "chip warn" }, "Schadsoftware") : null, f.patterns.slice(0, 4).map((p) => h("span", { class: "chip" }, p)),
      h("div", { class: "grow" }),
      h("a", { class: "btn small", href: "#/attacks?q=" + encodeURIComponent(sha) }, "Angriffe mit dieser Datei"),
      h("button", { type: "button", class: "btn small", onclick: () => { box.hidden = true; history.replaceState(null, "", "#/funde"); } }, "Schließen")),
    h("div", { class: "fd-facts" }, facts.map(([k, v]) => h("div", null, h("div", { class: "k" }, k), h("div", { class: "v" }, v)))),
    si && si.hash_mismatch ? h("div", { class: "msg warn" }, "Der Inhalt passt nicht zum Hash im Dateinamen: Die Datei wurde nachträglich verändert.") : null,
    nav, body);
  show(subs.some(([s]) => s === V.sub) ? V.sub : "inhalt");
}

function caseBody(k, d) {
  const f = d.file, si = d.info;
  if (k === "inhalt") {
    const left = d.script ? h("div", { class: "fd-box" }, h("h3", null, "Inhalt", h("span", { class: "r" }, `${d.script.length} Zeilen · nur als Text, nie ausgeführt · Adressen markiert`)), codeBox(d.script))
      : h("div", { class: "fd-box" }, h("h3", null, "Inhalt"), h("p", { class: "muted", style: { margin: 0 } },
        si ? "Programme und Archive zeigt die Web-UI nie als Inhalt. Was sich aus den Zeichenketten lesen ließ, steht unter „Eingebettete Ziele“." : "Die Datei liegt nicht (mehr) vor: " + (f.missing || "unbekannt") + "."));
    return h("div", { class: "fd-cols" }, left, h("div", { class: "fd-side" },
      h("div", { class: "fd-box" }, h("h3", null, "Einordnung"), h("p", { style: { margin: 0 } }, summarize(d))),
      h("div", { class: "fd-box" }, h("h3", null, "Erkannte Muster"), f.patterns.length ? h("div", { class: "fd-chips" }, f.patterns.map((p) => h("span", { class: "chip" }, p))) : h("span", { class: "muted" }, "keine")),
      h("div", { class: "fd-box" }, h("h3", null, "Merkmale"), h("dl", { class: "fd-kv" },
        dl("Format", si ? si.type : "–"), si && si.interpreter ? dl("Interpreter", h("span", { class: "mono" }, si.interpreter)) : null,
        dl("Plattform", si && si.arch ? si.arch + (si.static ? ", statisch gelinkt" : "") : "–"), dl("Zeichenketten", si ? fmtNum(si.strings) : "–"),
        si && si.truncated ? dl("Untersucht", "nur der Anfang (Datei sehr groß)") : null,
        d.quarantine ? dl("Geholt", [fmtDateTime(d.quarantine.fetched), " von ", h("span", { class: "mono" }, d.quarantine.host || "?"), d.quarantine.content_type ? " · " + d.quarantine.content_type : ""]) : dl("Geholt", "von Cowrie beim Angriff"),
        dl("Ablage", "Quarantäne bzw. Cowrie-Downloads; nicht ausführbar, nie über die Web-UI")))));
  }
  if (k === "stufen") {
    const src = h("div", { class: "fd-box" }, h("h3", null, "Woher die Datei kam", h("span", { class: "r" }, `${d.sources.length} Adresse${d.sources.length === 1 ? "" : "n"}`)),
      d.sources.length ? h("table", { class: "fd-mini" }, h("thead", null, h("tr", null, ["Adresse", "Benutzt", "Angreifer", "Zuletzt", "URLhaus"].map((t) => h("th", null, t)))),
        h("tbody", null, d.sources.map((u) => h("tr", null, h("td", { class: "mono wrap" }, u.url, h("div", null, h("a", { class: "small", href: attSearch(u.url) }, "Angriffe mit dieser Adresse"))), h("td", { class: "num" }, u.uses ? fmtNum(u.uses) + "×" : "–"),
          h("td", { class: "num" }, u.n_ips || "–"), h("td", { class: "muted" }, ago(u.last)), h("td", { title: u.note || "" }, stBadge(u.urlhaus || "")))))) : h("div", { class: "muted" }, "Keine Adresse bekannt (z. B. per SFTP hochgeladen)."));
    if (!d.stages.length) return src;
    const got = d.stages.filter((s) => s.fetch === "ok").length;
    return h("div", { class: "stack" }, src, h("div", { class: "fd-box" }, h("h3", null, "Nachlade-Stufen", h("span", { class: "r" }, `Adressen in der Datei · ${got} geholt`)),
      h("table", { class: "fd-mini" }, h("thead", null, h("tr", null, ["Adresse", "Benutzt", "Holen", "Datei", "URLhaus"].map((t) => h("th", null, t)))),
        h("tbody", null, d.stages.map((s) => h("tr", { class: s.sha256 ? "click" : "", onclick: s.sha256 ? () => openOther(s.sha256) : null },
          h("td", { class: "mono wrap" }, s.url),
          h("td", { class: "num" }, s.seen ? fmtNum(s.seen) + "×" : h("span", { class: "muted" }, "nie")),
          h("td", null, s.why ? stBadge("skipped", "nie: " + s.why) : s.fetch === "ok" ? stBadge("ok", "geholt") : s.fetch === "error" ? stBadge("error", s.error || "Fehler") : h("span", { class: "muted" }, s.seen ? "nicht versucht" : "nicht benutzt, nicht geholt")),
          h("td", null, s.sha256 ? [h("span", { class: "fd-hash" }, shortSha(s.sha256)), h("div", { class: "muted small" }, [s.type, s.arch].filter(Boolean).join(" · "))] : "–"),
          h("td", null, stBadge(s.urlhaus || ""))))))),
      h("p", { class: "muted small" }, "Der Hive holt nur Adressen, die ein Angreifer wirklich benutzt hat, nie die aus einer Datei. Platzhalter wie $a stehen hier so, wie sie in der Datei stehen."));
  }
  if (k === "ziele") {
    const list = [];
    if (si) {
      for (const [kind, vals] of [["url", si.urls], ["ip", si.ips], ["pool", si.pools], ["wallet", si.wallets]]) for (const v of vals || []) list.push([kind, v]);
    }
    return h("div", { class: "fd-box" }, h("h3", null, "Eingebettete Ziele", h("span", { class: "r" }, "aus Zeichenketten und Inhalt der Datei")),
      list.length ? list.map(([kind, v]) => h("div", { class: "fd-ioc" }, h("span", { class: "t" }, KIND[kind]), h("span", { class: "mono wrap" }, v),
        h("a", { class: "small", href: attSearch(v), title: "Sucht über den ganzen gespeicherten Zeitraum in Befehlen, Adressen und entschlüsselten Inhalten" }, "In Angriffen suchen"))) : h("div", { class: "muted" }, si ? "Keine Adressen, IPs, Pools oder Wallets gefunden." : "Datei nicht untersucht."),
      h("p", { class: "muted small", style: { margin: "10px 0 0" } }, "Eingebettete Ziele werden nie aufgerufen und nie gemeldet, nur angezeigt."));
  }
  if (k === "netz") {
    return h("div", { class: "fd-cols" },
      h("div", { class: "fd-box" }, h("h3", null, "Angreifer mit dieser Datei", h("span", { class: "r" }, fmtNum(d.attackers.length))),
        d.attackers.length ? h("table", { class: "fd-mini" }, h("thead", null, h("tr", null, ["IP", "Herkunft", "Adressen", "Dateien", "AbuseIPDB"].map((t) => h("th", null, t)))),
          h("tbody", null, d.attackers.map((a) => h("tr", null, h("td", null, h("a", { class: "mono", href: "#/attacker/" + encodeURIComponent(a.ip) }, a.ip)),
            h("td", null, cc(a.country), " ", h("span", { class: "muted small" }, a.as_org || "")), h("td", { class: "num" }, a.urls || "–"), h("td", { class: "num" }, a.files || "–"),
            h("td", { title: a.note || "" }, stBadge(a.abuse || "", a.abuse === "ok" ? "gemeldet" : a.abuse === "dry" ? "würde melden" : undefined)))))) : h("div", { class: "muted" }, "unbekannt")),
      h("div", { class: "fd-box" }, h("h3", null, "Weitere Dateien vom selben Server", h("span", { class: "r" }, fmtNum(d.same_host.length))),
        d.same_host.length ? h("table", { class: "fd-mini" }, h("tbody", null, d.same_host.map((x) => h("tr", { class: "click", onclick: () => openOther(x.sha256) },
          h("td", { class: "mono wrap" }, x.url), h("td", { class: "muted small" }, [x.type, x.arch].filter(Boolean).join(" · ")), h("td", { class: "fd-hash" }, shortSha(x.sha256)))))) : h("div", { class: "muted" }, "keine")));
  }
  if (k === "protokoll") {
    return h("div", { class: "fd-box" }, h("h3", null, "Prüfprotokoll", h("span", { class: "r" }, "was den Hive verließ, wörtlich (ohne Schlüssel), und was zurückkam")),
      d.audit.length ? h("div", { class: "fd-audit" }, d.audit.map((e) => h("div", { class: "e " + ((ST[e.status] || ["", "dry"])[1]) },
        h("div", { class: "h" }, h("span", { class: "muted num" }, e.status === "wait" ? "jetzt" : fmtDateTime(e.time)), h("b", null, (PROV[e.kind] || [e.kind])[0]), stBadge(e.status),
          h("span", { class: "mono wrap small" }, e.subject)),
        e.detail ? h("div", { class: "small fd-detail" }, e.detail) : null,
        e.error ? h("div", { class: "small fd-errtext" }, e.error) : null,
        e.sent ? h("pre", { class: "fd-pre" }, e.sent) : null))) : h("div", { class: "muted" }, "Noch nichts gemeldet oder versucht."),
      h("p", { class: "muted small", style: { margin: "10px 0 0" } }, "Einträge vor Version 0.9.5 haben keinen Wortlaut. DShield-Sendungen fassen alle Angreifer einer Stunde zusammen und stehen in den Einstellungen."));
  }
  if (k === "extern") {
    const mb = d.external.malwarebazaar, uh = d.external.urlhaus || [];
    const kv = (obj) => h("dl", { class: "fd-kv" }, Object.entries(obj || {}).filter(([, v]) => v !== null && v !== "" && !(Array.isArray(v) && !v.length)).map(([k2, v]) => dl(k2, Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v))));
    const look = (label, path) => {
      const out = h("div", { class: "small muted" });
      return h("div", null, h("button", { type: "button", class: "btn small", onclick: async (e) => {
        e.target.disabled = true;
        out.textContent = "frage nach …";
        try { const r = await api(path); mount(out, kv(r.data)); } catch (err) { out.textContent = err.message; }
        e.target.disabled = false;
      } }, label), out);
    };
    return h("div", { class: "fd-cols" },
      h("div", { class: "fd-box" }, h("h3", null, "MalwareBazaar", mb ? h("span", { class: "r" }, "gespeichert " + relTime(mb.at)) : null),
        mb ? kv(mb.data) : look("Jetzt bei MalwareBazaar nachschlagen", "lookup/malwarebazaar?hash=" + f.sha256)),
      h("div", { class: "fd-box" }, h("h3", null, "URLhaus"),
        d.sources.map((u) => { const c = uh.find((x) => x.url === u.url); return h("div", { class: "fd-ext" }, h("div", { class: "mono wrap small" }, u.url), c ? kv(c.data) : look("Jetzt bei URLhaus nachschlagen", "lookup/urlhaus?url=" + encodeURIComponent(u.url))); }),
        d.sources.length ? null : h("div", { class: "muted" }, "Keine Adresse bekannt.")));
  }
  if (k === "ki") {
    return h("div", { class: "fd-box" }, h("h3", null, "Antworten des Sprachmodells an diese Angreifer", h("span", { class: "r" }, "letzte 30 Tage")),
      d.ai.length ? d.ai.map((x) => h("div", { class: "fd-ai" }, h("div", { class: "muted small" }, fmtDateTime(x.t), " · ", h("a", { class: "mono", href: "#/attacker/" + encodeURIComponent(x.ip) }, x.ip), " · ", x.kind === "web" ? "Web" : "Shell", x.cached ? " · aus dem Speicher" : ""),
        h("div", { class: "q mono" }, x.input), h("div", { class: "a mono" }, x.output))) : h("div", { class: "muted" }, "Keine Antworten des Sprachmodells an diese Angreifer."),
      h("p", { class: "muted small", style: { margin: "10px 0 0" } }, "Eine KI-Auswertung des ganzen Angriffs gibt es auf der Seite des Angreifers unter „Angriffsbericht“."));
  }
  return null;
}

// openOther: andere Datei in der Fallakte öffnen (gleiche Ansicht, kein Neuladen der Liste)
function openOther(sha) {
  location.hash = "#/funde?f=" + sha;
}

function dl(k, v) { return [h("dt", null, k), h("dd", null, v)]; }

const URL_RE = /((?:https?|ftp|tftp):\/\/[^\s'"`;|&<>)]+)/g;
function codeBox(lines) {
  return h("div", { class: "fd-code" }, lines.map((l) => {
    const parts = [];
    let last = 0;
    for (const m of l.matchAll(URL_RE)) {
      if (m.index > last) parts.push(l.slice(last, m.index));
      parts.push(h("span", { class: "u" }, m[0]));
      last = m.index + m[0].length;
    }
    parts.push(l.slice(last));
    return h("div", { class: /^\s*#/.test(l) ? "c" : "" }, parts);
  }));
}

// summarize: kurze Einordnung aus den Merkmalen (feste Regeln, kein Sprachmodell)
function summarize(d) {
  const f = d.file, si = d.info;
  if (!si) return "Die Datei liegt nicht (mehr) vor; bekannt sind nur Hash und Herkunft.";
  const s = [];
  if (si.type === "Skript") s.push(`Ein Skript (${si.interpreter || "Shell"})`);
  else if (si.type) s.push(`Ein ${si.type}` + (si.arch ? ` für ${si.arch}` : ""));
  if (si.packed) s.push(`gepackt mit ${si.packed}`);
  if (si.static) s.push("statisch gelinkt (läuft ohne Bibliotheken, typisch für Botnetze auf Routern)");
  let t = s.join(", ") + ".";
  if (d.stages.length) t += ` Es enthält ${d.stages.length} weitere Adresse${d.stages.length === 1 ? "" : "n"}; ${d.stages.filter((x) => x.fetch === "ok").length} davon hat der Hive geholt.`;
  if ((si.pools || []).length || (si.wallets || []).length) t += " Mining-Pool bzw. Wallet deuten auf einen Krypto-Miner.";
  if ((si.ips || []).length) t += ` Eingebettete IP-Adressen: ${si.ips.slice(0, 3).join(", ")}.`;
  if (f.ips.length) t += ` Geladen von ${f.ips.length} Angreifer${f.ips.length === 1 ? "" : "n"} in ${f.sessions || 0} Sitzung${f.sessions === 1 ? "" : "en"}.`;
  return t;
}
