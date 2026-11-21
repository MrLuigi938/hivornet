// Auswertungsseiten Analyse, Zugangsdaten und Tarpit (Konzept A aus konzepte/d-auswertung.html,
// beim Tarpit zusätzlich die Zeitleiste aus Konzept B).
//
// Wie überall: Angreiferdaten nur als Text (h() aus dom.js), nie als Link-Ziel außer
// den eigenen Routen (#/attacker/…, #/attacks?q=…).
import { h, s, mount, api, fmtNum, fmtDur, fmtTime, fmtDateTime, relTime, flag, hoverTip } from "./dom.js";
import { svcName, svcColor } from "./charts.js";
import { state, header, card, tile, cc, ipLink, svcBadge, MODE_NAME, route } from "./app.js";
import { cveInfo, cveBadges, cveDetails, kindChip, bruteStatsParam, bruteStatsNote } from "./attacks.js";
import { weeklyAICard } from "./ai.js";
import { dwellCard } from "./dwell.js";

// ---------- Bausteine ----------

const chip = (text, cls = "", title = null) => h("span", { class: "chip" + (cls ? " " + cls : ""), title }, text);
const find = (q) => "#/attacks?q=" + encodeURIComponent(q);
const SEV_COLOR = ["var(--sev0)", "var(--sev1)", "var(--sev2)", "var(--sev4)"];

function spark(values, color = "var(--accent)", { w = 64, hh = 18 } = {}) {
  const v = values && values.length > 1 ? values : [0, 0];
  const max = Math.max(1, ...v), n = v.length;
  const pts = v.map((x, i) => `${((i / (n - 1)) * w).toFixed(1)},${(hh - 2 - (x / max) * (hh - 4)).toFixed(1)}`).join(" ");
  return s("svg", { class: "aw-spark", width: w, height: hh, viewBox: `0 0 ${w} ${hh}`, preserveAspectRatio: "none", "aria-hidden": "true" },
    s("polyline", { points: `0,${hh} ${pts} ${w},${hh}`, fill: color, "fill-opacity": ".14", stroke: "none" }),
    s("polyline", { points: pts, fill: "none", stroke: color, "stroke-width": "1.5", "stroke-linejoin": "round", "vector-effect": "non-scaling-stroke" }));
}

// Rangliste mit Platz, Balken und optionalen Kennzeichen
function rank(rows, { key = (r) => r.key, n = (r) => r.n, link = null, extra = null, color = null, fmt = fmtNum, mono = false, empty = "Noch keine Daten." } = {}) {
  if (!rows || !rows.length) return h("div", { class: "empty" }, empty);
  const max = Math.max(1, ...rows.map(n));
  return h("ol", { class: "aw-rank" }, rows.map((r, i) => {
    const k = String(key(r));
    return h("li", null,
      h("span", { class: "i num" }, i + 1),
      h("span", { class: "k" + (mono ? " mono" : "") }, link ? h("a", { href: link(r), title: k }, k) : h("span", { title: k }, k), extra ? extra(r) : null),
      h("span", { class: "n num" }, fmt(n(r))),
      h("span", { class: "aw-bar" }, h("i", { style: { width: Math.max(1, (100 * n(r)) / max) + "%", background: color ? color(r) : null } })));
  }));
}

// Liste mit „Mehr anzeigen“: erst n Einträge, ein Klick zeigt alle (und wieder weniger).
function moreList(items, n, render) {
  if (!items || items.length <= n) return render(items || []);
  let all = false;
  const box = h("div");
  const btn = h("button", { class: "linklike aw-more" });
  const draw = () => {
    mount(box, render(all ? items : items.slice(0, n)));
    btn.textContent = all ? "Weniger anzeigen" : `Mehr anzeigen (${fmtNum(items.length - n)} weitere)`;
    btn.setAttribute("aria-expanded", String(all));
  };
  btn.onclick = () => { all = !all; draw(); };
  draw();
  return h("div", null, box, btn);
}
const rankMore = (rows, n, opts) => moreList(rows, n, (r) => rank(r, opts));

// Anteilsstreifen: [{label, n, color}]
function mix(parts, { height = 26, unit = "" } = {}) {
  const total = parts.reduce((a, p) => a + p.n, 0) || 1;
  return h("div", null,
    h("div", { class: "aw-mix", style: { height: height + "px" } }, parts.filter((p) => p.n > 0).map((p) => hoverTip(
      h("i", { style: { flex: String(Math.max(p.n, total * 0.03)), background: p.color } }, p.short ?? Math.round((100 * p.n) / total) + " %"),
      () => [p.label, [[unit || "Anzahl", p.fmt ? p.fmt(p.n) : fmtNum(p.n), p.color], ["Anteil", Math.round((100 * p.n) / total) + " %"]]]))),
    h("div", { class: "aw-legend" }, parts.map((p) => h("span", null, h("i", { class: "dot", style: { background: p.color } }), p.label))));
}

// Säulen: [{label, n}]
function columns(bars, { color = "var(--accent)", height = 130, fmt = fmtNum } = {}) {
  const max = Math.max(1, ...bars.map((b) => b.n));
  return h("div", { class: "aw-cols", style: { height: height + "px" } }, bars.map((b, i) => hoverTip(
    h("div", null, h("i", { style: { height: (100 * b.n) / max + "%", background: typeof color === "function" ? color(i) : color } }), h("span", null, b.label)),
    () => [b.label, [["Anzahl", fmt(b.n)]]])));
}

const code = (text, n, attrs = {}) => h("span", { class: "aw-code mono", title: text, ...attrs }, text, n != null ? h("em", null, fmtNum(n) + "×") : null);
const shortWallet = (w) => (w.length > 20 ? w.slice(0, 10) + "…" + w.slice(-6) : w);
const asyncTile = (label) => { const t = tile(label, "…", "…"); return { el: t, set: (v, hint) => { t.querySelector(".value").textContent = v; t.querySelector(".hint").textContent = hint || ""; } }; };

// ================= Analyse =================

const TOOL_GROUPS = [
  ["Scanner", "Scanner: ", "--s1"], ["SSH-Clients", "SSH-Client: ", "--s7"], ["Installiert", "installiert: ", "--s8"], ["Programme", "", "--s4"],
];

export async function viewAnalysis(el, ctx) {
  header("Analyse", { range: true });
  const q = (f, n = 25) => api(`stats/top?field=${f}&limit=${n}&range=${state.range}`);
  const [pd, tools, urls, wallets, pools, cves, ja4, hassh, httpfp] = await Promise.all([
    api("analysis/patterns?range=" + state.range), q("tool", 100), q("url", 60), q("wallet", 30), q("pool", 30), q("cve", 60), q("ja4", 30), q("hassh", 30), q("httpfp", 30)]);
  const pats = pd.patterns || [];
  const total = pats.reduce((a, p) => a + p.n, 0);
  const deepest = pats.length ? Math.max(...pats.map((p) => p.phase)) : -1;

  // Kennzahlen; drei davon kommen mit /api/campaigns bzw. /api/analysis/exploits nach (das dauert länger)
  const tCamp = asyncTile("Kampagnen"), tHp = asyncTile("Honeypot-Prüfungen"), tNoCve = asyncTile("Exploits ohne Zuordnung");
  const kpis = h("div", { class: "grid kpi" },
    tile("Muster-Treffer", fmtNum(total), `${fmtNum(pats.length)} verschiedene Muster`),
    tile("Weiteste Phase", deepest >= 0 ? pd.phases[deepest] : "–", deepest >= 0 ? pats.filter((p) => p.phase === deepest).map((p) => p.name).slice(0, 2).join(", ") : "noch nichts erkannt"),
    tCamp.el, tHp.el, tNoCve.el);

  // Vorgehen nach Phasen
  const phaseBoard = card("Vorgehen nach Phasen",
    h("p", { class: "sub" }, "Jedes erkannte Muster steht in der Phase, für die es steht. Farbe = Schwere, Linie = Verlauf im Zeitraum, Klick = passende Angriffe."),
    pats.length ? h("div", { class: "aw-phases" }, pd.phases.map((name, i) => {
      const list = pats.filter((p) => p.phase === i);
      return h("div", { class: "aw-phase" + (list.length ? "" : " empty-phase") },
        h("h3", null, h("span", null, name), h("span", { class: "muted num" }, fmtNum(list.reduce((a, p) => a + p.n, 0)))),
        list.length ? list.map((p) => h("a", { class: "aw-pat", href: find(p.name), title: p.desc, style: { "--c": SEV_COLOR[p.sev] || SEV_COLOR[1] } },
          h("div", { class: "t" }, h("b", null, p.name), h("span", { class: "num" }, fmtNum(p.n))),
          h("div", { class: "m" }, (p.mitre || []).slice(0, 1).map((m) => chip(m, "mitre")), spark(p.series, SEV_COLOR[p.sev] || SEV_COLOR[1]))))
          : h("div", { class: "muted aw-none" }, "Nichts beobachtet."));
    })) : h("div", { class: "empty" }, "Im Zeitraum keine Muster erkannt."));

  // Werkzeuge in vier Gruppen
  const groups = TOOL_GROUPS.map(([name, prefix, color]) => ({ name, color: `var(${color})`, rows: [] }));
  for (const t of tools) {
    const gi = TOOL_GROUPS.findIndex(([, p]) => p && t.key.startsWith(p));
    const g = groups[gi >= 0 ? gi : 3];
    if (gi < 0 && t.key.includes(": ")) continue; // andere Präfixe gehören nicht hierher
    if (g.rows.length < 40) g.rows.push({ key: gi >= 0 ? t.key.slice(TOOL_GROUPS[gi][1].length) : t.key, n: t.n });
  }
  const toolsCard = card("Werkzeuge der Angreifer",
    h("p", { class: "sub" }, "Links, womit sie kommen; rechts, was sie auf dem Gerät benutzen oder nachziehen wollen."),
    tools.length ? [mix(groups.map((g) => ({ label: g.name, n: g.rows.reduce((a, r) => a + r.n, 0), color: g.color, short: fmtNum(g.rows.reduce((a, r) => a + r.n, 0)) })), { height: 22, unit: "Treffer" }),
      h("div", { class: "aw-tools" }, groups.map((g) => h("div", null,
        h("div", { class: "aw-cap" }, h("i", { class: "dot", style: { background: g.color } }), g.name),
        rankMore(g.rows, 8, { color: () => g.color, empty: "Nichts beobachtet." }))))]
      : h("div", { class: "empty" }, "Noch keine Werkzeuge erkannt."));

  // Indikatoren: Nachlade-Adressen, Wallets, Pools
  const indItem = (kind, value, n, sub, cls = "") => h("div", { class: "aw-ind" },
    h("div", { class: "row" }, chip(kind, cls), h("span", { class: "muted" }, [sub, fmtNum(n) + "×"].filter(Boolean).join(" · "))),
    h("div", { class: "mono v", title: value }, value));
  const indicators = [
    ...urls.map((u) => indItem("Nachlade-Adresse", u.key, u.n, svcName(u.label || ""), "list")),
    ...wallets.map((w) => indItem("Wallet", shortWallet(w.key), w.n, w.label || "", "warn")),
    ...pools.map((p) => indItem("Mining-Pool", p.key, p.n, "")),
  ];
  const indCard = card("Indikatoren",
    h("p", { class: "sub" }, "Adressen, Wallets und Pools, die Angreifer benutzen wollten. Nicht aufrufen: Dahinter liegt in der Regel Schadsoftware."),
    indicators.length ? moreList(indicators, 10, (x) => x) : h("div", { class: "empty" }, "Im Zeitraum keine."));

  // Wiedererkannte Werkzeuge (Fingerabdrücke); IP-Anzahl kommt mit /api/campaigns
  const fps = [...hassh.map((x) => ({ kind: "HASSH", ...x })), ...ja4.map((x) => ({ kind: "JA4", ...x })), ...httpfp.map((x) => ({ kind: "HTTP", ...x }))]
    .sort((a, b) => b.n - a.n);
  const fpIPs = {};
  const fpCard = card("Wiedererkannte Werkzeuge",
    h("p", { class: "sub" }, "Fingerabdrücke aus SSH-Schlüsselaustausch, TLS und der Reihenfolge der HTTP-Kopfzeilen. Taucht einer bei mehreren IPs auf, ist es vermutlich dasselbe Programm."),
    fps.length ? moreList(fps, 8, (list) => list.map((f) => h("div", { class: "aw-fp" },
      chip(f.kind), h("a", { class: "mono k", href: find(f.key), title: f.key }, f.key),
      (fpIPs[f.kind + " " + f.key] = h("span", { class: "muted num" }, fmtNum(f.n) + "×")),
      f.kind === "HTTP" && f.label ? h("div", { class: "hdr" }, f.label.split(",").map((x) => h("span", null, x))) : null)))
      : h("div", { class: "empty" }, "Noch keine Fingerabdrücke."));

  // Kampagnen, Honeypot-Prüfungen, Lücken: Platzhalter, gefüllt nach /api/campaigns
  const campBody = h("div", { class: "muted" }, "Wird berechnet …");
  const hpBody = h("div", { class: "muted" }, "Wird berechnet …");
  const cveCard = card("Bekannte Lücken",
    rankMore(cves, 8, { key: (x) => x.key + " – " + (x.label || ""), link: (x) => find(x.key), color: () => "var(--sev4)", empty: "Keine Ausnutzungsversuche bekannter Lücken erkannt." }),
    h("p", { class: "muted aw-small" }, "Erkannt an der Anfrage; ein Treffer heißt, jemand hat es versucht, nicht, dass das Gerät verwundbar wäre. Proben und Produkte ohne CVE stehen in der Tabelle „Exploits nach Produkt“."));
  const xp = exploitSection(ctx, tNoCve);

  mount(el, h("div", { class: "stack" },
    h("p", { class: "sub" }, "Was Angreifer tun, nachdem sie verbunden sind: erkannte Vorgehensweisen nach Phasen, ihre Werkzeuge und woran man sie wiedererkennt. Die Zuordnung erfolgt nach festen Regeln auf dem Hive."),
    kpis, phaseBoard, xp.el,
    h("div", { class: "grid aw-21" }, toolsCard, indCard),
    h("div", { class: "grid two" }, fpCard,
      h("div", { class: "stack" }, card("Kampagnen", campBody), card("Honeypot-Prüfungen", hpBody), cveCard))));

  let d;
  try { d = await api("campaigns?range=" + state.range); } catch (e) { campBody.replaceWith(h("div", { class: "msg err" }, e.message)); return; }
  if (ctx && !ctx.current()) return;
  const camps = d.campaigns || [], hp = d.hp_check || { attacks: 0, ips: 0, continued: 0, recent: [] };
  tCamp.set(fmtNum(camps.length), camps.filter((c) => c.reasons.some((r) => r.startsWith("gleiche Wallet"))).length ? "auch über gleiche Wallet" : "gleiche Liste, Adresse oder Wallet");
  tHp.set(fmtNum(hp.attacks), hp.attacks ? `${fmtNum(hp.ips)} IPs · ${fmtNum(hp.continued)} haben weitergemacht` : "Shell-Echtheitstests");
  for (const t of d.tools || []) if (fpIPs[t.fingerprint]) fpIPs[t.fingerprint].textContent = `${fmtNum(t.n_ips)} IPs · ${fpIPs[t.fingerprint].textContent}`;

  campBody.replaceWith(camps.length ? moreList(camps, 6, (list) => h("div", null, list.map((c) => h("div", { class: "aw-item" },
    h("div", { class: "row" }, h("b", null, c.profile || "Kampagne"), c.reasons.map((r) => chip(r, r.startsWith("gleiche Wallet") ? "warn" : ""))),
    h("div", { class: "muted aw-small" }, `${fmtNum(c.n_ips)} IPs · ${fmtNum(c.attacks)} Angriffe · `, c.countries.map((x) => [flag(x.key), " "]),
      `· ${fmtDateTime(c.first)} – ${fmtDateTime(c.last)}`),
    h("div", { class: "aw-ips" }, moreList(c.ips, 8, (ips) => [ips.map((ip) => [ipLink(ip), " "]), c.n_ips > c.ips.length && ips.length === c.ips.length ? h("span", { class: "muted" }, `+${c.n_ips - c.ips.length}`) : null]))))))
    : h("div", { class: "empty" }, "Im Zeitraum keine zusammengehörigen Angreifer erkannt."));

  hpBody.replaceWith(h("div", null,
    h("p", { class: "sub" }, "Bots prüfen nach dem Login mit Rechenaufgaben, Subshells und Marker-Ausgaben, ob die Shell echt ist. Wer danach weitermacht, hat den Honeypot nicht erkannt."),
    hp.attacks ? [mix([{ label: "danach weitergemacht", n: hp.continued, color: "var(--good)" }, { label: "danach abgebrochen", n: hp.attacks - hp.continued, color: "var(--sev3)" }], { height: 20, unit: "Angriffe" }),
      moreList(hp.recent, 6, (list) => h("div", { class: "aw-list" }, list.map((x) => h("div", { class: "aw-item" },
        h("div", { class: "row" }, flag(x.country || ""), ipLink(x.ip), x.continued ? chip("weitergemacht", "ok") : chip("abgebrochen", "warn"), h("span", { class: "muted aw-right" }, relTime(x.last))),
        x.next ? h("div", { class: "mono aw-small muted", title: x.next }, "danach: " + x.next) : null))))]
      : h("div", { class: "empty" }, "Im Zeitraum keine Honeypot-Prüfungen.")));
}

// ---------- Exploits nach Produkt (hive/exploits.go, cvedb.go, cvesuggest.go) ----------

const isAdmin = () => state.user && state.user.role === "admin";
const CHECK = { kev: ["im KEV-Katalog", "ok"], nvd: ["in der NVD", "ok"], unbekannt: ["der NVD unbekannt", "warn"], offen: ["noch nicht geprüft", ""], "ungültig": ["ungültig", "warn"] };

// Tabelle Anfrage → Produkt → Lücke, darunter Exploits ohne Zuordnung mit Regelvorschlägen der KI.
function exploitSection(ctx, tileNoCve) {
  const body = h("div", { class: "muted" }, "Wird berechnet …");
  const lower = h("div");
  const el = card("Exploits nach Produkt",
    h("p", { class: "sub" }, "Welche Software Angreifer suchen (Probe) oder angreifen (Ausnutzung): Anfrage → Produkt → Lücke. CVSS und Beschreibung stammen von der NVD, EPSS (FIRST) schätzt die Wahrscheinlichkeit einer Ausnutzung in den nächsten 30 Tagen, KEV heißt: im CISA-Katalog der tatsächlich ausgenutzten Lücken. Ein Treffer heißt: versucht, nicht: verwundbar."),
    body, lower);
  let d = null, extra = { suggestions: [], rules: [] }, notice = "";
  let kind = "", filter = "";

  const load = async () => {
    try { d = await api("analysis/exploits?range=" + state.range); } catch (e) { mount(body, h("div", { class: "msg err" }, e.message)); return; }
    if (ctx && !ctx.current()) return;
    const nc = d.no_cve || { attacks: 0, paths: [] };
    tileNoCve.set(fmtNum(nc.attacks), nc.attacks ? "ohne Regel, Liste unter der Tabelle" : "alle Exploits zugeordnet");
    renderTable();
    await loadExtra();
  };
  const loadExtra = async () => {
    try { extra = await api("cve/suggestions"); } catch { extra = { suggestions: [], rules: [] }; }
    if (ctx && !ctx.current()) return;
    renderLower();
  };

  function renderTable() {
    const st = d.cvedb || {};
    const status = h("p", { class: "muted aw-small" },
      `${fmtNum(d.rules_total)} Regeln · im Zeitraum ${fmtNum(d.products)} Produkte, ${fmtNum(d.cves)} CVEs · ${fmtNum(d.exploit_attacks)}× Ausnutzung, ${fmtNum(d.probe_attacks)}× Probe. `,
      st.enabled ? (st.kev_count ? `CISA KEV: ${fmtNum(st.kev_count)} Einträge, Stand ${st.kev_version || fmtDateTime(st.kev_updated)}.` : "CISA KEV wird geladen.") : "Lückendetails sind ausgeschaltet (Einstellungen → Auswertung und KI).",
      st.pending ? ` NVD: ${fmtNum(st.pending)} Abfragen stehen aus.` : "",
      st.last_error ? h("span", { class: "warn-text" }, " Letzter Fehler: " + st.last_error) : null,
      d.truncated ? " Sehr viele Ereignisse: die ältesten fehlen." : "");
    const seg = h("div", { class: "seg", role: "group", "aria-label": "Art" }, [["", "Alle"], ["exploit", "Ausnutzungen"], ["probe", "Proben"]].map(([k, t]) =>
      h("button", { class: kind === k ? "on" : "", "aria-pressed": String(kind === k), onclick: () => { kind = k; renderTable(); } }, t)));
    const tbody = h("tbody");
    const drawRows = () => {
      const f = filter.trim().toLowerCase();
      const rows = (d.rows || []).filter((r) => (!kind || r.kind === kind) &&
        (!f || [r.product, r.name, r.cve || "", ...(r.paths || []).map((p) => p.key)].some((x) => x.toLowerCase().includes(f))));
      mount(tbody, rows.length ? rows.map(xpRow) : h("tr", null, h("td", { colspan: 7, class: "muted" }, d.rows && d.rows.length ? "Nichts passt zum Filter." : "Im Zeitraum keine Anfragen an bekannte Produkte erkannt.")));
    };
    const search = h("input", { type: "search", placeholder: "Produkt, CVE oder Pfad …", value: filter, "aria-label": "Tabelle filtern", class: "xp-search",
      oninput: (e) => { filter = e.target.value; drawRows(); } });
    drawRows();
    mount(body, status, h("div", { class: "filters" }, seg, search),
      h("div", { class: "tablewrap" }, h("table", { class: "xp-table" },
        h("thead", null, h("tr", null, ["Anfrage", "Produkt", "Art", "Lücke", "Angriffe", "IPs", "Zuletzt"].map((t) => h("th", null, t)))), tbody)));
  }

  function xpRow(r) {
    const badges = h("div", { class: "xp-badges" }, cveBadges(r.info));
    const cell = h("td", { colspan: 7 });
    const detail = h("tr", { class: "xp-detail", hidden: true }, cell);
    let info = r.info;
    if (r.cve && info && info.pending) cveInfo(r.cve, (i) => { info = i; mount(badges, cveBadges(i)); if (!detail.hidden) mount(cell, cveDetails(r.cve, i)); });
    const toggle = r.cve ? h("button", { class: "linklike mono", "aria-expanded": "false", "aria-label": r.cve + ": Details anzeigen", onclick: () => {
      detail.hidden = !detail.hidden;
      toggle.setAttribute("aria-expanded", String(!detail.hidden));
      if (!detail.hidden) mount(cell, cveDetails(r.cve, info));
    } }, r.cve) : h("span", { class: "muted" }, "ohne CVE");
    return [h("tr", null,
      h("td", { class: "xp-paths" }, (r.paths || []).map((p) => h("div", null, code(p.key, p.n)))),
      h("td", null, h("b", null, r.product), h("div", { class: "muted aw-small" }, r.name), r.custom ? h("span", { class: "chip", title: "Eigene Regel aus einem KI-Vorschlag" }, "eigene Regel") : null),
      h("td", null, kindChip(r.kind)),
      h("td", null, h("div", null, toggle), badges),
      h("td", { class: "num" }, h("a", { href: find("regel:" + r.id), title: "Passende Angriffe anzeigen" }, fmtNum(r.attacks)), h("div", { class: "muted aw-small" }, fmtNum(r.n) + " Anfr.")),
      h("td", { class: "num" }, fmtNum(r.ips)),
      h("td", { title: fmtDateTime(r.last) }, relTime(r.last))), detail];
  }

  function renderLower() {
    const nc = d.no_cve || { attacks: 0, paths: [] };
    const open = (extra.suggestions || []).filter((x) => x.status === "neu"), rules = extra.rules || [];
    const byPath = new Map(open.map((x) => [x.path, x]));
    const canAsk = isAdmin() && d.ai_enabled;
    const noCve = nc.attacks ? h("div", { class: "aw-note" },
      h("b", null, `${fmtNum(nc.attacks)} Exploit-Versuch${nc.attacks === 1 ? "" : "e"} ohne Zuordnung`),
      h("div", { class: "muted aw-small" }, canAsk
        ? "Keine Regel kennt diese Anfragen. „KI fragen“ schickt eine Beispielanfrage (ohne Host, Cookies, Zugangsdaten und eigene Adressen) an das Modell der KI-Auswertung; es schlägt Produkt, CVE und eine Regel vor. Übernommen wird nur, was du annimmst."
        : isAdmin() ? "Keine Regel kennt diese Anfragen. Mit eingerichteter KI-Auswertung (Einstellungen → Auswertung und KI) kann ein Modell Regeln vorschlagen." : "Keine Regel kennt diese Anfragen."),
      moreList(nc.paths, 10, (list) => h("div", { class: "xp-open" }, list.map((p) => {
        const path = p.key.replace(/^[A-Z]{3,7} /, "");
        const msg = h("span", { class: "muted aw-small" }, byPath.has(path) ? "Vorschlag liegt vor (unten)" : "");
        const btn = canAsk ? h("button", { class: "btn small", onclick: async () => {
          btn.disabled = true;
          msg.className = "muted aw-small";
          msg.textContent = "Das Modell arbeitet …";
          try { await api("cve/suggest", { method: "POST", body: { path: p.key } }); await loadExtra(); }
          catch (e) { msg.className = "warn-text aw-small"; msg.textContent = e.message; btn.disabled = false; }
        } }, byPath.has(path) ? "Erneut fragen" : "KI fragen") : null;
        return h("div", { class: "row" }, code(p.key, p.n), btn, msg);
      })))) : h("p", { class: "muted aw-small" }, "Alle Exploit-Versuche im Zeitraum sind einer Regel zugeordnet.");

    const suggBox = open.length ? [h("h3", null, "Regelvorschläge der KI"), h("div", { class: "aw-list" }, open.map(suggItem))] : null;
    const ruleBox = rules.length ? [h("h3", null, "Eigene Regeln"),
      h("p", { class: "muted aw-small" }, "Angenommene Vorschläge; sie gelten wie die eingebauten Regeln, auch für ältere Ereignisse (wird im Hintergrund nachgezählt)."),
      h("div", { class: "aw-list" }, rules.map((c) => h("div", { class: "aw-item" },
        h("div", { class: "row" }, kindChip(c.kind), h("b", null, c.product), h("span", null, c.name), c.cve ? h("span", { class: "mono" }, c.cve) : h("span", { class: "muted" }, "ohne CVE"),
          h("a", { class: "aw-right", href: find("regel:" + c.rule_id) }, "Angriffe"),
          isAdmin() ? h("button", { class: "linklike", onclick: async (e) => {
            if (!confirm(`Regel „${c.name}“ löschen? Passende Anfragen sind danach wieder ohne Zuordnung.`)) return;
            e.target.disabled = true;
            try { await api("cve/rules/" + c.id, { method: "DELETE" }); await load(); } catch (err) { alert(err.message); e.target.disabled = false; }
          } }, "Löschen") : null),
        h("code", { class: "mono aw-small xp-expr" }, c.expr))))] : null;
    mount(lower, h("h3", null, "Exploits ohne Zuordnung"), notice ? h("div", { class: "msg ok aw-small", role: "status" }, notice) : null, noCve, suggBox, ruleBox);
    notice = "";
  }

  function suggItem(x) {
    const [chk, cls] = CHECK[x.cve_check] || [x.cve_check || "", ""];
    const msg = h("span", { class: "aw-small" });
    const act = (what) => async (e) => {
      e.target.disabled = true;
      try {
        const res = await api(`cve/suggestions/${x.id}/${what}`, { method: "POST" });
        notice = res.note || (what === "accept" ? "Regel übernommen. Sie gilt ab sofort; ältere Ereignisse werden im Hintergrund nachgezählt." : "Vorschlag verworfen.");
        await (what === "accept" ? load() : loadExtra());
      } catch (err) { msg.className = "warn-text aw-small"; msg.textContent = err.message; e.target.disabled = false; }
    };
    return h("div", { class: "aw-item xp-sugg" },
      h("div", { class: "row" }, kindChip(x.kind), h("b", null, x.product), h("span", null, x.name),
        x.cve ? [h("span", { class: "mono" }, x.cve), h("span", { class: "chip " + cls, title: "Prüfung der Nummer gegen CISA KEV und NVD" }, chk)] : h("span", { class: "muted" }, "ohne CVE"),
        h("span", { class: "muted aw-right" }, relTime(x.created))),
      h("div", { class: "aw-small" }, h("span", { class: "muted" }, "Pfad: "), h("span", { class: "mono" }, x.path)),
      x.explanation ? h("p", { class: "aw-small" }, x.explanation) : null,
      h("div", { class: "aw-small" }, h("span", { class: "muted" }, "Regel: "), h("code", { class: "mono xp-expr" }, x.expr || "(keine)")),
      x.problem ? h("div", { class: "msg warn aw-small" }, "Nicht übernehmbar: " + x.problem) : null,
      x.cve && x.cve_check !== "kev" && x.cve_check !== "nvd" ? h("div", { class: "muted aw-small" }, "Die CVE ist nicht bestätigt; beim Annehmen wird sie weggelassen und die Regel erkennt nur das Produkt.") : null,
      h("details", null, h("summary", { class: "aw-small" }, "An das Modell geschickt"), h("pre", { class: "json" }, x.sample)),
      isAdmin() ? h("div", { class: "row" },
        h("button", { class: "btn small primary", disabled: !!x.problem, onclick: act("accept") }, "Als Regel übernehmen"),
        h("button", { class: "btn small", onclick: act("discard") }, "Verwerfen"), msg) : null);
  }

  load();
  return { el };
}

// ================= Zugangsdaten =================

const PW_CLASSES = [["nur Ziffern", "var(--s1)"], ["nur Kleinbuchstaben", "var(--s3)"], ["Buchstaben und Ziffern", "var(--s4)"], ["mit Sonderzeichen", "var(--s5)"]];
function pwClass(p) {
  if (/^\d+$/.test(p)) return 0;
  if (/^[a-z]+$/.test(p)) return 1;
  if (/[^a-zA-Z0-9]/.test(p)) return 3;
  return 2;
}
const LEN_BUCKETS = [["≤ 4", 4], ["5–6", 6], ["7–8", 8], ["9–12", 12], ["> 12", Infinity]];

// Zweck eines HTTP-Pfads (nur zur Gruppierung in der Anzeige)
const PATH_CATS = [
  ["KI und MCP", /\/(mcp|sse|v1\/(models|chat|completions)|api\/(generate|tags|chat)|ollama)\b/i],
  ["VPN und Firewall", /\/(remote\/(login|fgt_lang)|dana-na|vpn|global-protect|ssl-vpn|\+cscoe\+|owa|ecp)\b/i],
  ["Kamera und Router", /\/(SDK\/|cgi-bin|boaform|HNAP1|GponForm|goform|onvif|ISAPI|setup\.cgi|webLanguage)/i],
  ["Docker und Cloud", /\/(version|info|containers|images|_ping|v1\.\d+|v2\/_catalog|api\/v1\/namespaces|metadata)\b/i],
  ["Geheimnisse", /\/(\.env|\.git|\.aws|wp-config|config\.(php|json|yml)|backup|.*\.(sql|bak|zip))/i],
  ["CMS und Admin", /\/(wp-|xmlrpc|administrator|phpmyadmin|pma|manager\/html|admin)\b/i],
  ["Anmeldeseiten", /\/(login|signin|auth|user\/login)/i],
  ["PHP-Lücken", /\.php|phpunit|eval-stdin|invokefunction/i],
];
const pathCat = (p) => (PATH_CATS.find(([, re]) => re.test(p)) || [""])[0];

// Art eines User-Agents
function uaFamily(ua) {
  if (/bot|crawl|spider|scan|genome|infrawatch|censys|shodan|expanse|netcraft|internetmeasurement|zgrab|l9|nuclei|masscan/i.test(ua)) return "Bot oder Scanner";
  if (/curl|wget|python|go-http|java|okhttp|libwww|httpx|aiohttp|axios|node|^mozilla\/5\.0 \(compatible\)$/i.test(ua) || !/mozilla/i.test(ua)) return "Werkzeug";
  return "Browser-Imitat";
}
const UA_COLOR = { "Bot oder Scanner": "var(--s3)", "Browser-Imitat": "var(--s2)", Werkzeug: "var(--s1)" };
const HP_CHECK = /check_[0-9a-f]{16,}_|v=outer;|dGVzdA==|'a b;\$\(\)'/;

export async function viewCreds(el) {
  header("Zugangsdaten und Muster", { range: true });
  const nb = bruteStatsParam(); // ohne Dauer-Brute-Force (attacks.js)
  const q = (f, n = 25) => api(`stats/top?field=${f}&limit=${n}&range=${state.range}` + nb);
  const [sum, users, pws, pws100, combos, cmds, paths, uas, clients, snmp, sip, dns] = await Promise.all([
    api("creds/summary?range=" + state.range), q("username", 100), q("password", 100), q("password", 100), q("cred", 100), q("command", 100), q("path", 100),
    q("useragent", 100), q("client", 60), q("snmp", 60), q("sip", 60), q("dns", 60)]);
  const pct = (a, b) => (b ? Math.round((100 * a) / b) + " %" : "–");
  const credExtra = (r) => [r.rare ? chip("ungewöhnlich", "rare", "Nicht in gängigen Standard- und Werkslisten") : null, r.list ? chip(r.list + "-Liste", "list", "Stammt aus der bekannten Liste dieses Botnetzes") : null];

  // Passwort-Anatomie aus den 100 häufigsten Passwörtern
  const cls = [0, 0, 0, 0], lens = LEN_BUCKETS.map(() => 0);
  for (const p of pws100) { cls[pwClass(p.key)] += p.n; lens[LEN_BUCKETS.findIndex(([, m]) => p.key.length <= m)] += p.n; }

  // Befehle nach Dienst
  const bySvc = new Map();
  for (const c of cmds) { const k = c.label || "?"; if (!bySvc.has(k)) bySvc.set(k, []); bySvc.get(k).push(c); }

  // Pfade nach Zweck
  const cats = new Map(); let other = 0;
  for (const p of paths) { const c = pathCat(p.key); if (c) cats.set(c, (cats.get(c) || 0) + p.n); else other += p.n; }

  // User-Agents nach Art
  const fam = new Map();
  for (const u of uas) fam.set(uaFamily(u.key), (fam.get(uaFamily(u.key)) || 0) + u.n);

  const udp = (title, list, chipEl) => list.length ? [h("h3", { class: "aw-h3" }, chipEl, title), moreList(list, 10, (l) => h("div", null, l.map((x) => code(x.key, x.n))))] : null;

  mount(el, h("div", { class: "stack" },
    h("p", { class: "sub" }, "Womit Angreifer sich anmelden wollen und was sie danach eingeben. Ein Klick auf einen Eintrag zeigt die Angriffe, in denen er vorkam."),
    bruteStatsNote(() => route({ quiet: true })),
    h("div", { class: "grid kpi" },
      tile("Login-Versuche", fmtNum(sum.cred_total || sum.username_total), "im Zeitraum"),
      tile("Verschiedene Benutzernamen", fmtNum(sum.username_distinct)),
      tile("Verschiedene Passwörter", fmtNum(sum.password_distinct), sum.password_distinct ? `${pct(sum.password_once, sum.password_distinct)} nur einmal probiert` : null),
      tile("Aus der Mirai-Liste", pct(sum.botnet, sum.cred_total), `${fmtNum(sum.botnet)} Versuche mit kennzeichnenden Mirai-Passwörtern`)),
    h("div", { class: "grid two" },
      card("Wie die Passwörter gebaut sind",
        h("p", { class: "sub" }, "Zeichenarten und Länge der 100 häufigsten Passwörter, gewichtet nach Versuchen."),
        pws100.length ? [mix(PW_CLASSES.map(([label, color], i) => ({ label, color, n: cls[i] })), { unit: "Versuche" }),
          columns(LEN_BUCKETS.map(([label], i) => ({ label: label + " Zeichen", n: lens[i] })), { color: "var(--s7)" })] : h("div", { class: "empty" }, "Noch keine Passwörter.")),
      card("Kombinationen",
        h("p", { class: "sub" }, "Markiert, was aus der Mirai-Liste stammt oder in keiner Werksliste steht (deutet auf gezielte Angriffe oder abgeflossene Zugangsdaten)."),
        rankMore(combos, 10, { link: (r) => find(r.key), extra: credExtra, mono: true, color: (r) => (r.list ? "var(--sev4)" : r.rare ? "var(--sev2)" : null) }))),
    h("div", { class: "grid two" },
      card("Benutzernamen", rankMore(users, 10, { link: (r) => find(r.key), extra: credExtra, mono: true })),
      card("Passwörter", rankMore(pws, 10, { link: (r) => find(r.key), extra: credExtra, mono: true, color: (r) => PW_CLASSES[pwClass(r.key)][1] }),
        h("div", { class: "aw-legend" }, PW_CLASSES.map(([l, c]) => h("span", null, h("i", { class: "dot", style: { background: c } }), l))))),
    h("div", { class: "grid aw-21" },
      card("Befehle nach Dienst",
        h("p", { class: "sub" }, "Eingaben nach Login und Protokoll-Befehle, je Dienst zusammengefasst."),
        bySvc.size ? [...bySvc].map(([svc, list]) => [
          h("h3", { class: "aw-h3" }, svcBadge(svc), h("span", { class: "muted num" }, fmtNum(list.reduce((a, c) => a + c.n, 0)) + "×"),
            list.some((c) => HP_CHECK.test(c.key)) ? chip("Honeypot-Prüfung erkannt", "warn") : null),
          moreList(list, 14, (l) => h("div", null, l.map((c) => h("a", { class: "aw-codelink", href: find(c.key) }, code(c.key, c.n)))))])
          : h("div", { class: "empty" }, "Noch keine Befehle.")),
      card("HTTP-Pfade nach Zweck",
        h("p", { class: "sub" }, "Die 100 häufigsten Pfade, einer Kategorie zugeordnet: Was suchen Web-Scanner?"),
        rank([...cats].map(([key, n]) => ({ key, n })).sort((a, b) => b.n - a.n), { color: () => "var(--s2)", empty: "Keine zuordenbaren Pfade." }),
        other ? h("p", { class: "muted aw-small" }, `Ohne Kategorie: ${fmtNum(other)} Anfragen (z. B. /, /favicon.ico).`) : null,
        h("h3", { class: "aw-h3" }, "Häufigste Pfade"),
        rankMore(paths, 8, { link: (r) => find(r.key), mono: true, extra: (r) => [pathCat(r.key) ? chip(pathCat(r.key)) : null, r.label && r.label !== "http" ? chip(svcName(r.label)) : null] }))),
    h("div", { class: "grid three" },
      card("Wer stellt die Web-Anfragen?",
        uas.length ? [mix([...fam].map(([label, n]) => ({ label, n, color: UA_COLOR[label] })), { unit: "Anfragen" }),
          h("div", { class: "aw-gap" }), rankMore(uas, 6, { extra: (r) => chip(uaFamily(r.key)) })] : h("div", { class: "empty" }, "Keine Web-Anfragen.")),
      card("SSH- und andere Clients", rankMore(clients, 8, { mono: true, extra: (r) => (r.label ? svcBadge(r.label) : null) })),
      card("UDP: SIP, SNMP, DNS",
        h("p", { class: "sub" }, "UDP-Absender lassen sich fälschen. IP-Adressen in SIP-Adressen sind durch ‹IP› ersetzt."),
        sip.length || snmp.length || dns.length ? [udp("SIP-Ziele", sip, chip("SIP")), udp("Community-Strings", snmp, chip("SNMP")), udp("Abfragen", dns, chip("DNS"))]
          : h("div", { class: "empty" }, "Keine UDP-Anfragen.")))));
}

// ================= Tarpit =================

const HIST_LABELS = ["< 10 s", "10–60 s", "1–10 Min", "10–60 Min", "1–6 Std", "> 6 Std"];

function timelineCard(tl, byIP) {
  const segs = tl.segments || [];
  if (!segs.length) return card("Zeitleiste: wer wann festhing", h("div", { class: "empty" }, "Im Zeitraum niemand im Tarpit."));
  const from = tl.from, to = tl.to, span = Math.max(1, to - from);
  const ips = byIP.slice(0, 10).map((r) => r.src_ip);
  const lanes = new Map(ips.map((ip) => [ip, []]));
  for (const sg of segs) lanes.get(sg.src_ip)?.push(sg);
  // Achse: 6 Marken über den Zeitraum
  const ticks = Array.from({ length: 6 }, (_, i) => from + (span * i) / 5);
  const tickFmt = span > 2 * 86400000 ? (t) => new Intl.DateTimeFormat("de-DE", { weekday: "short", day: "2-digit" }).format(new Date(t)) : (t) => fmtTime(t);
  return card("Zeitleiste: wer wann festhing",
    h("p", { class: "sub" }, "Die zehn Angreifer mit der längsten Gesamtzeit. Jeder Balken ist eine festgehaltene Verbindung, Farbe = Dienst."),
    h("div", { class: "aw-gantt" },
      byIP.slice(0, 10).map((r) => h("div", { class: "row" },
        h("span", { class: "who" }, flag(r.country || ""), " ", ipLink(r.src_ip), r.as_org ? h("span", { class: "muted" }, " " + r.as_org) : null),
        h("div", { class: "lane" }, (lanes.get(r.src_ip) || []).map((sg) => {
          const start = Math.max(from, sg.ts - sg.tarpit_ms), left = ((start - from) / span) * 100, width = Math.max(0.4, ((sg.ts - start) / span) * 100);
          return hoverTip(h("i", { style: { left: left + "%", width: Math.min(width, 100 - left) + "%", background: svcColor(sg.service) } }),
            () => [r.src_ip, [["Dienst", `${svcName(sg.service)} :${sg.dst_port}`, svcColor(sg.service)], ["Ende", fmtDateTime(sg.ts)], ["Dauer", fmtDur(sg.tarpit_ms)]]]);
        })),
        h("span", { class: "num muted tot" }, fmtDur(r.tarpit_ms)))),
      h("div", { class: "axis" }, h("span"), h("div", null, ticks.map((t) => h("span", null, tickFmt(t)))), h("span"))));
}

export async function viewTarpit(el, ctx) {
  header("Tarpit", { range: true });
  const d = await api("tarpit?range=" + state.range);
  const active = [];
  for (const sn of d.sensors) for (const l of sn.listeners || []) if (l.mode !== "emulate") active.push({ ...l, sensor: sn.sensor });
  const held = d.held || [];
  const clock = (ms) => { const t = Math.max(0, Math.floor(ms / 1000)); return `${Math.floor(t / 3600)}:${String(Math.floor(t / 60) % 60).padStart(2, "0")}:${String(t % 60).padStart(2, "0")}`; };
  const timer = (since) => h("span", { class: "num tick", "data-since": since }, clock(Date.now() - since));
  const ports = d.by_port || [], byIP = d.by_ip || [], longest = d.longest || [];
  const avg = d.connections ? d.total_ms / d.connections : 0;
  const topPort = ports[0];

  const hero = h("section", { class: "card aw-hero" },
    h("div", null, h("div", { class: "muted aw-small" }, "Verschwendete Angreiferzeit im Zeitraum"), h("div", { class: "big num" }, fmtDur(d.total_ms))),
    h("div", { class: "eq" },
      h("div", null, h("b", { class: "num" }, fmtNum(d.connections)), h("span", null, "festgehaltene Verbindungen")),
      h("div", null, h("b", { class: "num" }, avg ? fmtDur(avg) : "–"), h("span", null, "im Schnitt je Verbindung")),
      h("div", null, h("b", { class: "num" }, longest[0] ? fmtDur(longest[0].tarpit_ms) : "–"), h("span", null, longest[0] ? "Rekord: " + longest[0].src_ip : "Rekord")),
      h("div", null, h("b", { class: "num" }, fmtNum(d.active)), h("span", null, "gerade festgehalten")),
      h("div", null, h("b", { class: "num" }, topPort && d.total_ms ? Math.round((100 * topPort.tarpit_ms) / d.total_ms) + " %" : "–"), h("span", null, topPort ? `der Zeit über ${svcName(topPort.service)}` : "Hauptport"))),
    h("div", { class: "aw-hero-spark" }, spark(d.series || [], "var(--s7)", { w: 240, hh: 64 }), h("div", { class: "muted aw-small" }, "Verlauf im Zeitraum")));

  const heldCard = card("Gerade festgehalten" + (held.length ? ` (${fmtNum(held.length)})` : ""),
    held.length ? h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Angreifer", "Herkunft", "Dienst", "Modus", "Seit", "Dauer"].map((t) => h("th", null, t)))),
      h("tbody", null, held.map((x) => h("tr", null,
        h("td", null, ipLink(x.ip)), h("td", null, cc(x.country, x.country_name), " ", [x.city, x.as_org].filter(Boolean).join(" · ")),
        h("td", null, svcBadge(x.service, x.port)), h("td", null, MODE_NAME[x.mode] || x.mode), h("td", { class: "num" }, fmtTime(x.since)), h("td", null, h("b", null, timer(x.since))))))))
      : h("div", { class: "empty" }, d.active ? "Der Honeypot meldet die festgehaltenen Verbindungen erst ab Version 0.5.2 einzeln." : "Gerade hängt niemand im Tarpit."));

  const portMax = Math.max(1, ...ports.map((p) => p.tarpit_ms));
  const portCard = card("Welcher Port am meisten bremst",
    ports.length ? [mix(ports.map((p) => ({ label: `${p.dst_port} · ${svcName(p.service)}`, n: p.tarpit_ms, color: svcColor(p.service), short: String(p.dst_port), fmt: fmtDur })), { height: 28, unit: "Zeit" }),
      h("div", { class: "tablewrap" }, h("table", null,
        h("thead", null, h("tr", null, h("th", null, "Port"), h("th", { class: "num" }, "Verbindungen"), h("th", { class: "num" }, "Gesamt"), h("th", { class: "num" }, "Ø"), h("th", null, ""))),
        h("tbody", null, ports.map((p) => h("tr", null, h("td", null, svcBadge(p.service, p.dst_port)), h("td", { class: "num" }, fmtNum(p.n)), h("td", { class: "num" }, fmtDur(p.tarpit_ms)),
          h("td", { class: "num" }, fmtDur(p.n ? p.tarpit_ms / p.n : 0)), h("td", null, h("span", { class: "aw-bar inline" }, h("i", { style: { width: (100 * p.tarpit_ms) / portMax + "%", background: svcColor(p.service) } }))))))))]
      : h("div", { class: "empty" }, "Noch keine festgehaltenen Verbindungen."));

  const histCard = card("Wie lange Scanner hängen bleiben",
    h("p", { class: "sub" }, "Verteilung der Haltedauer. Ganz rechts: Programme ohne Zeitlimit."),
    d.connections ? columns(HIST_LABELS.map((label, i) => ({ label, n: (d.hist || [])[i] || 0 })), { height: 170, color: (i) => `color-mix(in oklab, var(--s7) ${40 + i * 12}%, var(--surface-3))` })
      : h("div", { class: "empty" }, "Noch keine Daten."));

  mount(el, h("div", { class: "stack" },
    h("p", { class: "sub" }, "Im Tarpit-Modus bekommen Angreifer extrem langsam endlose Daten. Jede Sekunde hier ist Zeit, in der ihr Scanner nichts anderes angreift."),
    hero,
    timelineCard(d.timeline || {}, byIP),
    h("div", { class: "grid two" }, portCard, histCard),
    card("Am längsten festgehalten",
      rank(byIP, { key: (r) => r.src_ip, n: (r) => r.tarpit_ms, fmt: fmtDur, link: (r) => "#/attacker/" + encodeURIComponent(r.src_ip), color: () => "var(--s7)",
        extra: (r) => [flag(r.country || ""), r.as_org ? h("span", { class: "muted" }, r.as_org) : null, r.service ? svcBadge(r.service) : null, h("span", { class: "muted" }, fmtNum(r.n) + " Verb.")], empty: "Noch keine." })),
    heldCard,
    card("Ports mit Tarpit oder Hybrid (jetzt)", active.length ? h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Sensor", "Port", "Dienst", "Modus", "Gerade festgehalten", "Offen", "Verbindungen seit Start"].map((t) => h("th", null, t)))),
      h("tbody", null, active.map((l) => h("tr", null, h("td", null, l.sensor), h("td", { class: "num" }, l.port), h("td", null, svcName(l.service)),
        h("td", null, MODE_NAME[l.mode] || l.mode), h("td", { class: "num" }, fmtNum(l.tarpitting)), h("td", { class: "num" }, fmtNum(l.active)), h("td", { class: "num" }, fmtNum(l.total)))))))
      : h("div", { class: "empty" }, "Kein Port im Tarpit- oder Hybrid-Modus. Umschalten unter Einstellungen."))));
  ctx.every(1000, () => { el.querySelectorAll(".tick").forEach((t) => { t.textContent = clock(Date.now() - Number(t.dataset.since)); }); });
  ctx.every(10000, () => { if (!document.hidden && location.hash === "#/tarpit") route({ quiet: true }); });
}

// ================= Erkenntnisse (hive/insights.go) =================
// Konzept A aus konzepte/e-erkenntnisse.html (Lagebericht: Meldungsstrom „Was ist neu“ mit
// Ranglisten), dazu aus Konzept B der Kalenderstreifen der Wiederkehrer und die Paare
// „Erkunden → Angreifen“.

const FS_FIELDS = [["password", "Passwörter"], ["cred", "Kombinationen"], ["command", "Befehle"], ["path", "HTTP-Pfade"], ["url", "Nachlade-Adressen"],
  ["wallet", "Wallets"], ["hassh", "SSH-Fingerabdrücke"], ["ja4", "TLS-Fingerabdrücke"], ["tag", "Angriffsmuster"], ["cve", "Lücken (CVE)"],
  ["port", "Ziel-Ports"], ["useragent", "User-Agents"]];
const STUFE_N = ["Abtasten", "Versuche", "Login angenommen", "Befehle ausgeführt", "Datei nachgeladen"];
const NEWS = {
  fam: ["F", "var(--sev4)", "Neue Familie"], first: ["1", "var(--s7)", "Erstmals gesehen"], rec: ["↻", "var(--s4)", "Wiederkehrer"],
  hand: ["→", "var(--s2)", "Erkunden → Angreifen"], spike: ["▲", "var(--sev3)", "Spitze"],
};
const dayLabel = (t) => {
  const d = new Date(t), today = new Date();
  const k = (x) => x.getFullYear() * 400 + x.getMonth() * 31 + x.getDate();
  if (k(d) === k(today)) return "Heute";
  if (k(d) === k(new Date(Date.now() - 86400000))) return "Gestern";
  return new Intl.DateTimeFormat("de-DE", { weekday: "long", day: "2-digit", month: "2-digit" }).format(d);
};

// Meldungen aus allen Erkenntnissen, neueste zuerst
function newsItems(d, fs) {
  const items = [];
  for (const f of d.families.filter((x) => x.new)) {
    items.push({ k: "fam", t: f.first, title: "Neue Familie: " + f.name,
      text: `${fmtNum(f.attacks)} Angriff${f.attacks === 1 ? "" : "e"} von ${fmtNum(f.ips)} IP${f.ips === 1 ? "" : "s"}, bis „${STUFE_N[f.stufe]}“.`,
      chips: [f.attacks === 1 ? chip("Ausreißer") : null, ...(f.tags || []).slice(0, 2).map((t) => chip(t.label || t.key))], fam: f });
  }
  for (const [field, title] of FS_FIELDS) {
    const rows = (fs && fs[field]) || [];
    if (!rows.length) continue;
    const top = rows.slice(0, 3).map((x) => ((field === "tag" || field === "cve") && x.label ? x.label : x.key));
    items.push({ k: "first", t: Math.max(...rows.map((x) => x.first)), title: `Erstmals gesehen: ${title}`,
      text: `${fmtNum(rows.length)} neu, z. B. ${top.join(" · ")}`,
      links: rows.slice(0, 6).map((x) => ({ q: (field === "tag" || field === "cve") && x.label ? x.label : x.key, label: (field === "tag" || field === "cve") && x.label ? x.label : x.key })) });
  }
  for (const r of d.recurring.slice(0, 6)) {
    items.push({ k: "rec", t: r.last, title: "Wiederkehrer: " + r.ip, ip: r.ip,
      text: `${fmtNum(r.attacks)} Angriffe an ${fmtNum(r.days)} Tag${r.days === 1 ? "" : "en"}, höchste Stufe „${STUFE_N[r.stufe]}“${r.as_org ? " · " + r.as_org : ""}.` });
  }
  for (const x of d.handoffs) {
    items.push({ k: "hand", t: x.attack_at, title: "Erkunden → Angreifen",
      text: `${x.scan_ip} tastete ab, ${fmtDur(x.attack_at - x.scan_at)} später griff ${x.attack_ip} mit demselben seltenen Fingerabdruck an (${x.profile || STUFE_N[x.stufe]}).`,
      chips: [chip(x.fingerprint.split(" ")[0])] });
  }
  for (const s of d.spikes || []) {
    items.push({ k: "spike", t: s.hour, title: "Spitze bei " + svcName(s.service),
      text: `${fmtNum(s.count)} Verbindungen in einer Stunde, sonst etwa ${fmtNum(Math.round(s.mean))}.` });
  }
  return items.sort((a, b) => b.t - a.t).slice(0, 80);
}

function newsFeed(items) {
  const state = { kind: "all" };
  const filters = h("div", { class: "filters" });
  const feed = h("div", { class: "aw-feed" });
  const render = () => {
    mount(filters, h("button", { class: "fchip" + (state.kind === "all" ? " on" : ""), onclick: () => { state.kind = "all"; render(); } }, "Alles ", h("b", null, fmtNum(items.length))),
      Object.entries(NEWS).map(([k, [, c, l]]) => {
        const n = items.filter((i) => i.k === k).length;
        return n ? h("button", { class: "fchip" + (state.kind === k ? " on" : ""), onclick: () => { state.kind = k; render(); } }, h("i", { style: { background: c } }), l, " ", h("b", null, fmtNum(n))) : null;
      }));
    let day = "";
    const shown = items.filter((i) => state.kind === "all" || i.k === state.kind);
    mount(feed, shown.length ? shown.flatMap((i) => {
      const dl = dayLabel(i.t);
      const sep = dl !== day ? [h("div", { class: "aw-daysep" }, (day = dl))] : [];
      const [ico, c] = NEWS[i.k];
      return [...sep, h("div", { class: "aw-news", style: { "--c": c } },
        h("div", { class: "when num" }, fmtTime(i.t), h("div", null, relTime(i.t))),
        h("div", { class: "ico" }, ico),
        h("div", { class: "body" },
          h("div", { class: "t" }, h("b", null, i.title), ...(i.chips || []).filter(Boolean)),
          h("div", { class: "s" }, i.text),
          i.ip ? h("div", { class: "aw-small" }, ipLink(i.ip)) : null,
          i.links ? h("div", { class: "aw-small aw-links" }, i.links.map((l) => h("a", { class: "aw-code mono", href: find(l.q), title: l.label }, clipStr(l.label, 40)))) : null,
          i.fam ? h("details", null, h("summary", null, "Befehle und IPs"),
            h("div", { class: "term" }, i.fam.example.map((cmd) => h("div", null, h("span", { class: "cmd" }, cmd)))),
            h("div", { class: "aw-ips" }, i.fam.sample_ips.map((ip) => [ipLink(ip), " "]))) : null))];
    }) : h("div", { class: "empty" }, "Im Zeitraum nichts Neues."));
  };
  render();
  return [filters, feed];
}
const clipStr = (s, n) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

// Kalenderstreifen der Wiederkehrer (Konzept B): je IP eine Zeile, je Tag bzw. Stunde ein Feld
function recurringHeat(d) {
  if (!d.recurring.length) return h("div", { class: "empty" }, "Niemand kam mehr als zweimal.");
  const nb = d.buckets || 7, step = d.bucket_ms || 86400000;
  const max = Math.max(1, ...d.recurring.flatMap((r) => r.per_slot || []));
  const label = (i) => {
    const t = new Date(d.from + i * step);
    if (step < 86400000) return String(t.getHours()).padStart(2, "0");
    return String(t.getDate()).padStart(2, "0") + "." + (step > 86400000 ? String(t.getMonth() + 1).padStart(2, "0") + "." : "");
  };
  const every = nb > 14 ? Math.ceil(nb / 10) : 1;
  return h("div", { class: "aw-heat", style: { gridTemplateColumns: `minmax(130px, 200px) repeat(${nb}, minmax(0, 1fr)) 64px` } },
    h("span"), Array.from({ length: nb }, (_, i) => h("span", { class: "hd" }, i % every === 0 ? label(i) : "")), h("span"),
    d.recurring.map((r) => [
      h("span", { class: "who", title: r.as_org || "" }, flag(r.country || ""), " ", ipLink(r.ip)),
      (r.per_slot || []).map((n, i) => hoverTip(h("span", { class: "c", style: n ? { background: `color-mix(in srgb, ${SEV_COLOR[Math.min(3, Math.max(1, r.stufe - 1))]} ${25 + (75 * n) / max}%, var(--surface-3))` } : null }),
        () => [r.ip, [["Zeit", label(i) + (step < 86400000 ? " Uhr" : "")], ["Angriffe", fmtNum(n)]]])),
      h("span", { class: "muted aw-small num", style: { textAlign: "right" } }, `${fmtNum(r.days)} Tag${r.days === 1 ? "" : "e"}`)]));
}

// Paare Scanner → Angreifer (Konzept B)
function handoffPairs(d) {
  if (!d.handoffs.length) return h("div", { class: "empty" }, "Keine solchen Paare erkannt.");
  return moreList(d.handoffs, 12, (list) => h("div", { class: "aw-pairs" }, list.map((x) => h("div", null,
    h("div", { class: "aw-pair" },
      h("div", { class: "node", style: { "--c": "var(--sev0)" } }, ipLink(x.scan_ip), h("div", { class: "muted aw-small" }, "tastet ab · ", relTime(x.scan_at))),
      h("div", { class: "arrow" }, h("b", null, "→"), fmtDur(x.attack_at - x.scan_at)),
      h("div", { class: "node", style: { "--c": SEV_COLOR[Math.min(3, Math.max(1, x.stufe))] } }, ipLink(x.attack_ip), h("div", { class: "muted aw-small" }, x.profile || STUFE_N[x.stufe], " · ", relTime(x.attack_at)))),
    h("div", { class: "mono muted aw-small", style: { marginTop: "3px" } }, x.fingerprint)))));
}

export async function viewInsights(el, ctx) {
  header("Erkenntnisse", { range: true });
  const tNew = asyncTile("Neu seit gestern"), tFam = asyncTile("Angriffsfamilien"), tRec = asyncTile("Wiederkehrer"),
    tHand = asyncTile("Arbeitsteilung"), tSpike = asyncTile("Spitzen");
  const newsBody = h("div", { class: "muted" }, "Wird berechnet …");
  const famBody = h("div", { class: "muted" }, "…");
  const recBody = h("div", { class: "muted" }, "…");
  const handBody = h("div", { class: "muted" }, "…");
  mount(el, h("div", { class: "stack" },
    h("p", { class: "sub" }, "Was sich zu wissen lohnt, neueste Meldung oben: neue Angriffsfamilien, Erstmaliges, Wiederkehrer, Arbeitsteilung zwischen Scanner und Angreifer und ungewöhnliche Spitzen."),
    weeklyAICard(), // KI-Wochenbericht (hive/aiplus.go), nur wenn eingeschaltet
    h("div", { class: "grid kpi" }, tNew.el, tFam.el, tRec.el, tHand.el, tSpike.el),
    h("div", { class: "grid aw-21" },
      card("Was ist neu", newsBody),
      card("Angriffsfamilien", h("p", { class: "sub" }, "Angriffe mit ähnlicher Befehlsfolge; Adressen, Zahlen und Hashes zählen dabei als gleich."), famBody)),
    dwellCard(), // Verweildauer nach dem Login (hive/dwell.go)
    card("Wiederkehrer", h("p", { class: "sub" }, "IPs mit mindestens drei getrennten Angriffen im Zeitraum. Je Feld die Angriffe, Farbe nach höchster Stufe."), recBody),
    card("Erkunden → Angreifen", h("p", { class: "sub" }, "Ein seltener Fingerabdruck taucht erst beim Abtasten einer IP auf und binnen 48 Stunden bei einem Angriff einer anderen: vermutlich Arbeitsteilung zwischen Scanner und Angreifer."), handBody)));

  let d, fs = null;
  try {
    [d, fs] = await Promise.all([api("insights?range=" + state.range), api("firstseen?range=" + state.range).catch(() => null)]);
  } catch (e) { mount(newsBody, h("div", { class: "msg err" }, e.message)); return; }
  if (ctx && !ctx.current()) return;
  d.families = d.families || []; d.recurring = d.recurring || []; d.handoffs = d.handoffs || []; d.spikes = d.spikes || [];
  const items = newsItems(d, fs);
  const dayAgo = Date.now() - 86400000;
  const newCount = items.filter((i) => (i.k === "fam" || i.k === "first") && i.t >= dayAgo).length;
  tNew.set(fmtNum(newCount), "neue Familien und Erstmaliges");
  tFam.set(fmtNum(d.families.length), fmtNum(d.families.reduce((a, f) => a + f.attacks, 0)) + " Angriffe mit Befehlen");
  tRec.set(fmtNum(d.recurring.length), "IPs mit 3+ Angriffen");
  tHand.set(fmtNum(d.handoffs.length), "Scanner → Angreifer");
  tSpike.set(fmtNum(d.spikes.length), d.spikes.length ? "zuletzt " + relTime(d.spikes[0].hour) : "keine im Zeitraum");
  mount(newsBody, newsFeed(items));
  const famMax = Math.max(1, ...d.families.map((f) => f.attacks));
  mount(famBody, d.families.length ? moreList(d.families, 12, (list) => h("div", { class: "aw-famlist" }, list.map((f) => h("details", null,
    h("summary", null,
      h("span", { class: "k" }, h("i", { class: "dot", style: { background: SEV_COLOR[Math.min(3, Math.max(1, f.stufe - 1))] } }), h("span", { title: f.name }, f.name), f.new ? chip("neu", "warn") : null),
      h("span", { class: "n muted aw-small num" }, `${fmtNum(f.attacks)} · ${fmtNum(f.ips)} IPs`),
      h("span", { class: "aw-bar" }, h("i", { style: { width: (100 * f.attacks) / famMax + "%", background: SEV_COLOR[Math.min(3, Math.max(1, f.stufe - 1))] } }))),
    h("div", { class: "aw-small muted" }, STUFE_N[f.stufe], " · seit ", fmtDateTime(f.first), " · zuletzt ", relTime(f.last), " · ", f.countries.map((c) => [flag(c.key), " "])),
    h("div", { class: "term" }, f.example.map((c) => h("div", null, h("span", { class: "cmd" }, c)))),
    h("div", { class: "aw-ips" }, f.sample_ips.map((ip) => [ipLink(ip), " "]), f.ips > f.sample_ips.length ? h("span", { class: "muted" }, `+${f.ips - f.sample_ips.length}`) : null)))))
    : h("div", { class: "empty" }, "Im Zeitraum keine Angriffe mit Befehlen."));
  mount(recBody, moreList(d.recurring, 15, (list) => recurringHeat({ ...d, recurring: list })));
  mount(handBody, handoffPairs(d));
}

// ================= Wie Shodan dich sieht (hive/exposure.go) =================

export function exposureCard() {
  const body = h("div");
  const ipIn = h("input", { placeholder: "öffentliche IP (leer = selbst ermitteln)", style: { width: "260px" } });
  const render = (e) => {
    if (!e || !e.ip) { mount(body, h("p", { class: "muted" }, "Noch nicht abgefragt.")); return; }
    if (!ipIn.value) ipIn.value = e.ip;
    mount(body,
      e.honeypot ? h("div", { class: "msg err" }, "Shodan führt diese Adresse als Honeypot. Scanner, die Shodan nutzen, meiden das Gerät. Ein anderes Geräteprofil oder andere Banner können helfen; die Einstufung ändert sich erst beim nächsten Scan.")
        : e.indexed ? h("div", { class: "msg ok" }, "Shodan kennt die Adresse, hält sie aber nicht für einen Honeypot.")
          : h("div", { class: "msg" }, "Shodan kennt diese Adresse (noch) nicht."),
      e.indexed ? h("div", { class: "facts-row" },
        h("div", { class: "k" }, "Adresse"), h("div", { class: "v mono" }, e.ip + (e.detected ? " (selbst ermittelt)" : "")),
        h("div", { class: "k" }, "Offene Ports"), h("div", { class: "v mono" }, e.ports.join(", ") || "–"),
        h("div", { class: "k" }, "Kennzeichen"), h("div", { class: "v" }, e.tags.length ? e.tags.map((t) => chip(t, t === "honeypot" ? "warn" : "")) : "–"),
        h("div", { class: "k" }, "Hostnamen"), h("div", { class: "v mono" }, e.hostnames.join(", ") || "–"),
        h("div", { class: "k" }, "Software"), h("div", { class: "v mono" }, e.cpes.join(", ") || "–"),
        h("div", { class: "k" }, "Lücken laut Shodan"), h("div", { class: "v mono" }, e.vulns.join(", ") || "–")) : null,
      h("p", { class: "muted aw-small" }, "Stand: ", fmtDateTime(e.fetched), ". Shodan erfährt dabei nur die öffentliche Adresse; zum Ermitteln wird api.ipify.org gefragt."));
  };
  const btn = h("button", { class: "btn small", onclick: async () => {
    btn.disabled = true;
    mount(body, h("span", { class: "muted" }, "frage Shodan …"));
    try { render(await api("exposure", { method: "POST", body: { ip: ipIn.value.trim() } })); } catch (e) { mount(body, h("div", { class: "msg err" }, e.message)); }
    btn.disabled = false;
  } }, "Bei Shodan nachsehen");
  api("exposure").then(render).catch(() => render(null));
  return card("Wie Shodan dich sieht", h("p", { class: "sub" }, "Was Shodan über deinen Anschluss weiß: offene Ports, erkannte Software und ob das Gerät als Honeypot markiert ist."),
    h("div", { class: "btnrow" }, ipIn, btn), body);
}
