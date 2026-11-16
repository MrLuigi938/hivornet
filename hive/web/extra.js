// Zusatzfunktionen der UI: Live-Karte, Analyse, Angriffsbericht mit KI-Auswertung,
// Terminal-Mitschnitt, AbuseIPDB-Abgleich und die Einstellungen dazu.
//
// Wie überall gilt: Angreiferdaten werden nur als Text eingefügt (h() aus dom.js).
// Adressen aus Angreiferdaten werden nie zu Links gemacht.
import { h, s, mount, api, fmtNum, fmtDur, fmtTime, fmtDateTime, relTime, flag } from "./dom.js";
import { worldMap, toplist, svcName, countryName } from "./charts.js";
import { state, header, card, tile, cc, ipLink, svcBadge, describe, isNoise, TYPE_NAME } from "./app.js";

// ---------- Standort des Honeypots (Ziel der Angriffslinien) ----------

let homeCache = null;
export async function homeLocation() {
  if (!homeCache) {
    try { homeCache = (await api("extras")).extras.home; } catch { homeCache = null; }
  }
  return homeCache || { lat: 51.1, lon: 10.4, label: "Honeypot" };
}

// ---------- Live-Karte ----------

export async function viewLive(el, ctx) {
  header("Live-Karte");
  const [mp, ctry, home] = await Promise.all([api("stats/map?range=24h"), api("stats/top?field=country&limit=100&range=24h"), homeLocation()]);
  const map = worldMap(mp, { home, large: true, countries: ctry });
  const ticker = h("ul", { class: "ticker" });
  const perMin = tile("Angriffe pro Minute", "0", "Verbindungen in den letzten 60 s");
  const countries = tile("Länder", "0", "in den letzten 10 Minuten");
  const last = tile("Letzter Angriff", "–");
  const svcBox = h("div");
  const stamps = [];            // Zeitpunkte der Verbindungen (60 s)
  const seen = new Map();       // Land -> letzter Zeitpunkt
  const bySvc = new Map();      // Dienst -> Anzahl seit Öffnen der Ansicht

  const refresh = () => {
    const now = Date.now();
    while (stamps.length && now - stamps[0] > 60000) stamps.shift();
    for (const [k, t] of seen) if (now - t > 600000) seen.delete(k);
    perMin.querySelector(".value").textContent = fmtNum(stamps.length);
    countries.querySelector(".value").textContent = fmtNum(seen.size);
    mount(svcBox, toplist([...bySvc].map(([key, n]) => ({ key: svcName(key), n })).sort((a, b) => b.n - a.n).slice(0, 8)));
  };
  const addLine = (e, hot) => {
    // gleiche IP, gleiche Art direkt hintereinander: Zähler hochzählen statt neuer Zeile
    const key = `${e.src_ip}|${e.type}|${e.service}`, top = ticker.firstChild;
    if (top && top.dataset.key === key) {
      const n = Number(top.dataset.n) + 1;
      top.dataset.n = n;
      top.querySelector(".when").textContent = fmtTime(e.ts);
      let x = top.querySelector(".xn");
      if (!x) { x = h("span", { class: "xn" }); top.children[1].append(x); }
      x.textContent = "×" + fmtNum(n);
      if (hot) mount(top.querySelector(".what"), ipLink(e.src_ip), " ", TYPE_NAME[e.type] || e.type, ": ", describe(e));
      top.style.animation = "none"; void top.offsetWidth; top.style.animation = "";
      return;
    }
    const where = [e.city, e.country_name].filter(Boolean).join(", ") || (e.country === "LAN" ? "Lokales Netz" : "unbekannt");
    ticker.prepend(h("li", { class: hot ? "hot" : "", dataset: { key, n: 1 } },
      h("span", { class: "when" }, fmtTime(e.ts)),
      h("span", null, cc(e.country, e.country_name), " ", where, " → ", svcBadge(e.service, e.dst_port)),
      h("span", { class: "what" }, ipLink(e.src_ip), " ", hot ? [TYPE_NAME[e.type] || e.type, ": ", describe(e)] : null)));
    while (ticker.children.length > 60) ticker.lastChild.remove();
  };

  mount(el, h("div", { class: "stack" },
    h("p", { class: "sub" }, "Jede rote Linie ist ein gerade aktiver Angreifer: vom Ursprung zum Honeypot (",
      home.label || "Honeypot", "). Sie bleibt stehen, solange er etwas tut, und verschwindet kurz nach seiner letzten Verbindung. ",
      "Der kurze Puls am Ursprung zeigt jede neue Verbindung, seine Farbe den Dienst. Den Standort stellst du unter Einstellungen ein."),
    h("div", { class: "live-grid" },
      h("div", { class: "stack" },
        h("section", { class: "card" }, h("div", { class: "head" }, h("h2", null, "Herkunft, letzte 24 Stunden"), h("div", { class: "grow" }), map.controls), map.el),
        h("div", { class: "grid kpi" }, perMin, countries, last)),
      h("div", { class: "stack" },
        card("Gerade eben", ticker, h("div", { class: "empty", id: "ticker-empty" }, "Warte auf den nächsten Angriff …")),
        card("Dienste seit Öffnen der Karte", svcBox)))));
  refresh();

  ctx.live((e) => {
    map.track(e); // Linie bleibt, solange der Angreifer aktiv ist
    if (e.type === "connect") {
      stamps.push(Date.now());
      if (e.country && e.country !== "LAN") seen.set(e.country, Date.now());
      bySvc.set(e.service, (bySvc.get(e.service) || 0) + 1);
      mount(last.querySelector(".value"), e.country && e.country !== "LAN" ? [flag(e.country), " ", countryName(e.country)] : e.country === "LAN" ? "Lokales Netz" : "–");
      addLine(e, false);
    } else if (!isNoise(e) && e.type !== "tls" && e.type !== "client_version" && e.type !== "fingerprint") {
      addLine(e, true);
    } else return;
    const empty = document.getElementById("ticker-empty");
    if (empty) empty.remove();
    refresh();
  });
  ctx.every(5000, refresh);
}

// ---------- Analyse: Muster, Werkzeuge, Nachlade-Adressen ----------

export async function viewAnalysis(el) {
  header("Analyse", { range: true });
  const q = (f, n = 25) => api(`stats/top?field=${f}&limit=${n}&range=${state.range}`);
  const [tags, tools, urls, clients, uas, cves, ja4, hassh, httpfp] = await Promise.all([q("tag"), q("tool", 60), q("url"), q("client", 15), q("useragent", 15),
    q("cve", 20), q("ja4", 15), q("hassh", 15), q("httpfp", 15)]);
  const installed = tools.filter((t) => t.key.startsWith("installiert: ")).map((t) => ({ key: t.key.slice(13), n: t.n }));
  const scanners = tools.filter((t) => t.key.startsWith("Scanner: ") || t.key.startsWith("SSH-Client: "));
  const programs = tools.filter((t) => !t.key.includes(": "));
  mount(el, h("div", { class: "stack" },
    h("p", { class: "sub" }, "Was Angreifer tun, nachdem sie verbunden sind: erkannte Vorgehensweisen, benutzte Programme und die Adressen, ",
      "von denen sie Schadcode nachladen. Die Zuordnung erfolgt nach festen Regeln auf dem Hive; gezählt wird seit der Aktualisierung auf diese Version."),
    card("Angriffsmuster", tags.length ? toplist(tags, { key: (x) => x.label || x.key, link: (x) => "#/attacks?q=" + encodeURIComponent(x.label || x.key) }) : h("div", { class: "empty" }, "Noch keine Muster erkannt."),
      tags.length ? h("p", { class: "muted", style: { margin: "10px 0 0", fontSize: "12.5px" } }, "Ein Klick zeigt die Angriffe mit diesem Muster.") : null),
    h("div", { class: "grid three" },
      card("Benutzte Programme", toplist(programs.slice(0, 20))),
      card("Installiert oder nachgezogen", installed.length ? toplist(installed.slice(0, 20)) : h("div", { class: "empty" }, "Noch nichts beobachtet.")),
      card("Scanner und Clients", toplist(scanners.slice(0, 20)))),
    card("Nachlade-Adressen",
      h("p", { class: "sub" }, "Von hier wollten Angreifer Dateien laden. Nicht aufrufen: Dahinter liegt in der Regel Schadsoftware."),
      urls.length ? h("ul", { class: "toplist" }, urls.map((u) => h("li", null,
        h("span", { class: "k", title: u.key }, u.key), h("span", { class: "n" }, fmtNum(u.n)))))
        : h("div", { class: "empty" }, "Noch keine.")),
    h("div", { class: "grid two" },
      card("SSH- und Client-Versionen", toplist(clients)),
      card("User-Agents", toplist(uas))),
    await campaignsCard(),
    card("Bekannte Lücken (CVE)", cves.length ? toplist(cves, { key: (x) => x.key + " – " + (x.label || ""), link: (x) => "#/attacks?q=" + encodeURIComponent(x.key) })
      : h("div", { class: "empty" }, "Noch keine Ausnutzungsversuche bekannter Lücken erkannt."),
      h("p", { class: "muted" }, "Erkannt an der Anfrage; ein Treffer heißt, jemand hat es versucht, nicht, dass das Gerät verwundbar wäre.")),
    h("div", { class: "grid three" },
      card("TLS-Fingerabdrücke (JA4)", toplist(ja4, { link: (x) => "#/attacks?q=" + encodeURIComponent(x.key) })),
      card("SSH-Fingerabdrücke (HASSH)", toplist(hassh, { link: (x) => "#/attacks?q=" + encodeURIComponent(x.key) })),
      card("Reihenfolge der HTTP-Kopfzeilen", toplist(httpfp, { key: (x) => x.key + "  " + (x.label || ""), link: (x) => "#/attacks?q=" + encodeURIComponent(x.key) }))),
    h("p", { class: "muted" }, "Den vollständigen Ablauf eines einzelnen Angreifers zeigt der Angriffsbericht auf der Seite der jeweiligen IP oder Sitzung.")));
}

// Kampagnen: IPs mit gleicher Zugangsdatenliste oder Nachlade-Adresse (hive/campaigns.go)
const STUFE_NAME = ["Abtasten", "Versuche", "Login angenommen", "Befehle ausgeführt", "Datei nachgeladen"];
async function campaignsCard() {
  let d;
  try { d = await api(`campaigns?range=${state.range}`); } catch (e) { return card("Kampagnen", h("div", { class: "msg err" }, e.message)); }
  const ipLinks = (ips) => ips.slice(0, 12).map((ip) => [h("a", { class: "mono", href: "#/attacker/" + encodeURIComponent(ip) }, ip), " "]);
  return card("Kampagnen",
    h("p", { class: "sub" }, "Angreifer, die zusammengehören: gleiche Liste von Zugangsdaten oder gleiche Nachlade-Adresse. ",
      "Gleiche Fingerabdrücke zeigen nur dasselbe Werkzeug und stehen darunter."),
    d.campaigns.length ? h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["IPs", "Gemeinsam", "Art", "Höchste Stufe", "Herkunft", "Zeitraum", "Beispiele"].map((t) => h("th", null, t)))),
      h("tbody", null, d.campaigns.slice(0, 30).map((c) => h("tr", null,
        h("td", null, h("b", null, fmtNum(c.n_ips)), " ", h("div", null, ipLinks(c.ips), c.n_ips > 12 ? h("span", { class: "muted" }, `+${c.n_ips - 12}`) : null)),
        h("td", null, c.reasons.join(", ")),
        h("td", null, c.profile),
        h("td", null, STUFE_NAME[c.stufe] || c.stufe),
        h("td", null, c.countries.map((x) => [flag(x.key), " ", fmtNum(x.n), " "]), c.n_asns ? h("span", { class: "muted" }, ` · ${fmtNum(c.n_asns)} Netze`) : null),
        h("td", { class: "num" }, fmtDateTime(c.first), " – ", fmtDateTime(c.last)),
        h("td", { class: "mono" }, [...(c.urls || []), ...(c.creds || []).slice(0, 4)].join("  ·  ")))))))
      : h("div", { class: "empty" }, "Im Zeitraum keine zusammengehörigen Angreifer erkannt."),
    d.tools.length ? [h("h3", null, "Gleiches Werkzeug (Fingerabdruck bei mindestens 3 IPs)"), h("ul", { class: "toplist" }, d.tools.map((f) => h("li", null,
      h("a", { class: "k mono", href: "#/attacks?q=" + encodeURIComponent(f.fingerprint.split(" ")[1] || f.fingerprint) }, f.fingerprint),
      h("span", { class: "n" }, `${fmtNum(f.n_ips)} IPs`))))] : null);
}

// Abfrage bei abuse.ch auf Knopfdruck; das Ergebnis erscheint hinter dem Knopf (nur Text).
function lookupBtn(name, path, fmt) {
  const out = h("span", { class: "muted" });
  const b = h("button", { class: "btn small", onclick: async () => {
    b.disabled = true;
    out.textContent = " frage " + name + " …";
    try { const d = await api(path); out.textContent = " " + fmt(d.data); } catch (e) { out.textContent = " " + e.message; }
    b.disabled = false;
  } }, name);
  return h("span", null, b, out);
}
const urlhausText = (d) => d.query_status === "no_results" ? "bei URLhaus unbekannt"
  : `URLhaus: ${d.threat || "gelistet"}, ${d.url_status === "online" ? "noch online" : d.url_status || "Status unbekannt"}` +
    (d.signatures && d.signatures.length ? ", " + d.signatures.join(", ") : "") + (d.tags && d.tags.length ? " · " + d.tags.join(", ") : "") +
    (d.date_added ? " · seit " + d.date_added : "");
const bazaarText = (d) => d.query_status === "hash_not_found" ? "bei MalwareBazaar unbekannt"
  : d.query_status !== "ok" ? "MalwareBazaar: " + d.query_status
  : `MalwareBazaar: ${d.signature || "ohne Familie"} (${d.file_type || "?"})` + (d.tags && d.tags.length ? " · " + d.tags.join(", ") : "") + (d.first_seen ? " · zuerst " + d.first_seen : "");

// ---------- Angriffskette (hive/chain.go) ----------
//
// Graph in sechs Phasen-Spalten (Erkundung → … → Ziel). Knoten: Ports, Anmeldungen,
// Exploits, Befehlsgruppen, Nachlade-Hosts, Dateien, Weiterleitungen; Pfeile: was folgte
// worauf (je Sitzung) und woher eine Datei kam. Klick auf einen Knoten zeigt Einzelheiten
// und hebt seine Verbindungen hervor. Angreiferdaten nur als Textknoten (s()/h()).
const CH = { colW: 204, nodeW: 176, nodeH: 50, gapY: 14, top: 44, left: 8 };
const KIND_NAME = { service: "Dienst", login: "Anmeldeversuche", login_ok: "Login angenommen", exploit: "Exploit", pattern: "Muster",
  commands: "Befehle", host: "Nachlade-Host", file: "Datei", forward: "Weiterleitung", prompt: "Login-Abfrage", web: "Web-Anfragen", more: "Sammelknoten" };
const short = (t, n) => (t.length > n ? t.slice(0, n - 1) + "…" : t);

// Hauptpfad: von jedem Anfang (Knoten ohne Vorgänger) der stärksten Verbindung folgen;
// gezeigt wird der Weg, der am weitesten kommt (höchste Phase, dann die meisten Schritte).
function mainPath(c) {
  if (!c.nodes.length) return [];
  const out = new Map(), hasIn = new Set(c.edges.map((e) => e.to));
  for (const e of c.edges) { if (!out.has(e.from)) out.set(e.from, []); out.get(e.from).push(e); }
  const byId = new Map(c.nodes.map((n) => [n.id, n]));
  const walk = (first) => {
    const path = [first], seen = new Set([first.id]);
    for (let cur = first; path.length < 12;) {
      const next = (out.get(cur.id) || []).filter((e) => !seen.has(e.to))
        .sort((a, b) => (b.n - a.n) || (byId.get(b.to).phase - byId.get(a.to).phase))[0];
      if (!next) break;
      cur = byId.get(next.to); seen.add(cur.id); path.push(cur);
    }
    return path;
  };
  const score = (p) => Math.max(...p.map((n) => n.phase)) * 100 + p.length;
  const starts = c.nodes.filter((n) => !hasIn.has(n.id));
  return (starts.length ? starts : [c.nodes[0]]).map(walk).sort((a, b) => score(b) - score(a))[0];
}

export function chainCard({ ip, session }) {
  const box = h("div", null, h("p", { class: "muted" }, "Lade Angriffskette …"));
  const query = ip ? "ip=" + encodeURIComponent(ip) : "session=" + encodeURIComponent(session);
  api("chain?" + query).then((c) => mount(box, chainView(c))).catch((e) => mount(box, h("div", { class: "msg err" }, "Angriffskette nicht verfügbar: " + e.message)));
  return card("Angriffskette", box);
}

function chainView(c) {
  if (!c.nodes.length) return h("div", { class: "empty" }, "Keine Ereignisse.");
  const byId = new Map(c.nodes.map((n) => [n.id, n]));
  const cols = c.phases.map(() => []);
  for (const n of c.nodes) cols[n.phase].push(n);
  const pos = new Map();
  cols.forEach((list, p) => list.forEach((n, i) => pos.set(n.id, { x: CH.left + p * CH.colW, y: CH.top + i * (CH.nodeH + CH.gapY) })));
  const rows = Math.max(1, ...cols.map((l) => l.length));
  const Wd = CH.left * 2 + c.phases.length * CH.colW - (CH.colW - CH.nodeW), Ht = CH.top + rows * (CH.nodeH + CH.gapY) + 16;

  // Kanten
  const maxN = Math.max(1, ...c.edges.map((e) => e.n));
  const edgeEls = c.edges.map((e) => {
    const a = pos.get(e.from), b = pos.get(e.to);
    if (!a || !b) return null;
    let d;
    if (b.x > a.x) { // vorwärts: rechts aus A, links in B
      const x1 = a.x + CH.nodeW, y1 = a.y + CH.nodeH / 2, x2 = b.x - 6, y2 = b.y + CH.nodeH / 2, mx = (x1 + x2) / 2;
      d = `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
    } else { // gleiche Spalte oder zurück: Bogen rechts herum
      const x1 = a.x + CH.nodeW, y1 = a.y + CH.nodeH * 0.7, x2 = b.x + CH.nodeW + 6, y2 = b.y + CH.nodeH * 0.3, bulge = 34 + Math.min(60, Math.abs(y2 - y1) / 4);
      // zurück: unten aus A heraus, unter den Knoten entlang, von unten in B hinein
      const low = Math.max(a.y, b.y) + CH.nodeH + 10;
      d = b.x < a.x ? `M${a.x + CH.nodeW / 2},${a.y + CH.nodeH} C${a.x + CH.nodeW / 2},${low} ${b.x + CH.nodeW / 2},${low} ${b.x + CH.nodeW / 2},${b.y + CH.nodeH + 6}`
        : `M${x1},${y1} C${x1 + bulge},${y1} ${x2 + bulge},${y2} ${x2},${y2}`;
    }
    const w = 1.2 + 2.8 * Math.log1p(e.n) / Math.log1p(maxN);
    return s("path", { class: "ch-edge" + (e.label ? " ch-flow" : ""), d, "stroke-width": w.toFixed(2), "marker-end": "url(#ch-arrow)", "data-from": e.from, "data-to": e.to },
      s("title", null, `${byId.get(e.from).label} → ${byId.get(e.to).label}${e.label ? " (" + e.label + ")" : ""}: ${e.n}×`));
  });

  const detail = h("div", { class: "ch-detail" }, h("p", { class: "muted" }, "Einen Knoten anklicken, um Einzelheiten und Verbindungen zu sehen."));
  let selected = null;
  const svg = s("svg", { class: "ch-svg", viewBox: `0 0 ${Wd} ${Ht}`, width: Wd, height: Ht, role: "img", "aria-label": "Angriffskette nach Phasen" },
    s("defs", null, s("marker", { id: "ch-arrow", viewBox: "0 0 10 10", refX: "9", refY: "5", markerWidth: "7", markerHeight: "7", orient: "auto-start-reverse" },
      s("path", { d: "M0,0 L10,5 L0,10 z", class: "ch-arrowhead" }))),
    c.phases.map((p, i) => s("g", null,
      s("rect", { class: "ch-col" + (cols[i].length ? "" : " empty"), x: CH.left + i * CH.colW - 4, y: 4, width: CH.nodeW + 8, height: Ht - 8, rx: 10 }),
      s("text", { class: "ch-phase", x: CH.left + i * CH.colW + CH.nodeW / 2, y: 26, "text-anchor": "middle" }, `${i + 1}. ${p}`),
      cols[i].length ? null : s("text", { class: "ch-none", x: CH.left + i * CH.colW + CH.nodeW / 2, y: CH.top + 26, "text-anchor": "middle" }, "–"))),
    s("g", null, edgeEls),
    c.nodes.map((n) => {
      const p = pos.get(n.id);
      const g = s("g", { class: "ch-node sev" + Math.min(4, n.sev), tabindex: 0, role: "button", "data-id": n.id, transform: `translate(${p.x},${p.y})` },
        s("title", null, `${n.label}${n.sub ? " – " + n.sub : ""} (${n.n}×)`),
        s("rect", { class: "ch-box", width: CH.nodeW, height: CH.nodeH, rx: 8 }),
        s("rect", { class: "ch-bar", width: 5, height: CH.nodeH, rx: 2 }),
        s("text", { class: "ch-label", x: 13, y: 20 }, short(n.label, 21)),
        s("text", { class: "ch-sub", x: 13, y: 38 }, short(n.sub || KIND_NAME[n.kind] || "", 24)),
        s("text", { class: "ch-n", x: CH.nodeW - 8, y: 20, "text-anchor": "end" }, n.n > 1 ? "×" + fmtNum(n.n) : ""));
      const pick = () => select(n.id);
      g.addEventListener("click", pick);
      g.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); pick(); } });
      return g;
    }));

  function select(id) {
    selected = selected === id ? null : id;
    svg.classList.toggle("focus", !!selected);
    svg.querySelectorAll(".ch-node").forEach((g) => g.classList.toggle("on", g.dataset.id === selected));
    const linked = new Set([selected]);
    svg.querySelectorAll(".ch-edge").forEach((p) => {
      const on = !!selected && (p.dataset.from === selected || p.dataset.to === selected);
      p.classList.toggle("on", on);
      if (on) { linked.add(p.dataset.from); linked.add(p.dataset.to); }
    });
    svg.querySelectorAll(".ch-node").forEach((g) => g.classList.toggle("near", !!selected && linked.has(g.dataset.id)));
    if (!selected) { mount(detail, h("p", { class: "muted" }, "Einen Knoten anklicken, um Einzelheiten und Verbindungen zu sehen.")); return; }
    const n = byId.get(selected);
    const ins = c.edges.filter((e) => e.to === n.id), outs = c.edges.filter((e) => e.from === n.id);
    const link = (id, extra) => h("button", { class: "linklike", onclick: () => select(id) }, byId.get(id).label, extra ? h("span", { class: "muted" }, " " + extra) : null);
    mount(detail,
      h("div", { class: "ch-dhead" }, h("span", { class: "badge stufe", style: { "--c": `var(--sev${Math.min(4, n.sev)})` } }, c.phases[n.phase]),
        h("strong", null, n.label), n.sub ? h("span", { class: "mono muted" }, n.sub) : null, h("span", { class: "badge" }, fmtNum(n.n) + "×")),
      h("p", { class: "muted" }, `${KIND_NAME[n.kind] || n.kind} · ${fmtDateTime(n.first)}` + (n.last > n.first ? ` bis ${fmtDateTime(n.last)}` : "")),
      n.mitre && n.mitre.length ? h("p", null, "MITRE ATT&CK: ", n.mitre.map((m) => [h("a", { class: "badge", href: "https://attack.mitre.org/techniques/" + m.replace(".", "/") + "/", target: "_blank", rel: "noopener noreferrer" }, m), " "])) : null,
      n.kind === "exploit" && /^CVE-/.test(n.label) ? h("p", null, h("a", { href: "https://nvd.nist.gov/vuln/detail/" + n.label, target: "_blank", rel: "noopener noreferrer" }, n.label + " in der NVD")) : null,
      h("div", { class: "grid two" },
        h("div", null, h("h3", null, "Folgte auf"), ins.length ? h("ul", { class: "plain" }, ins.map((e) => h("li", null, link(e.from, `${e.label ? e.label + ", " : ""}${e.n}×`)))) : h("p", { class: "muted" }, "Beginn")),
        h("div", null, h("h3", null, "Führte zu"), outs.length ? h("ul", { class: "plain" }, outs.map((e) => h("li", null, link(e.to, `${e.label ? e.label + ", " : ""}${e.n}×`)))) : h("p", { class: "muted" }, "Ende"))),
      n.examples && n.examples.length ? [h("h3", null, n.kind === "host" ? "Adressen (nicht aufrufen)" : "Beispiele"), h("div", { class: "term" }, n.examples.map((x) => h("div", null, x)))] : null);
  }

  const path = mainPath(c);
  const reached = Math.max(...c.nodes.map((n) => n.phase));
  return h("div", null,
    h("p", { class: "sub" }, `${fmtNum(c.events)} Ereignisse in ${fmtNum(c.sessions)} Sitzungen; erreicht bis Phase ${reached + 1} (${c.phases[reached]}).`,
      c.truncated ? " Nur die neuesten 5.000 Ereignisse." : ""),
    path.length > 1 ? h("div", { class: "ch-path" }, h("span", { class: "muted" }, "Hauptpfad: "),
      path.map((n, i) => [i ? h("span", { class: "ch-sep" }, " → ") : null, h("button", { class: "linklike", onclick: () => select(n.id) }, n.label)])) : null,
    h("div", { class: "ch-wrap" }, svg),
    h("div", { class: "ch-legend muted" }, "Farbe = Schwere wie die Stufen ",
      [0, 1, 2, 3, 4].map((i) => h("i", { class: "ch-dot", style: { background: `var(--sev${i})` } })),
      " · Strichstärke = Häufigkeit · orange Pfeile = Herkunft einer Datei bzw. Adresse"),
    detail);
}

// ---------- Angriffsbericht ----------

const SEV = { hoch: "Einstufung: hoch", mittel: "Einstufung: mittel", niedrig: "Einstufung: niedrig" };
const monoList = (items) => h("ul", { class: "mono-list" }, items.map((x) => h("li", null, x)));
const sha256 = /^[0-9a-f]{64}$/;

// Antwort der KI als einfaches Markdown darstellen: Überschriften, Listen, **fett**, `Code`,
// Code-Blöcke. Alles als Textknoten (h()), nie als HTML: die Antwort kann Angreifertext enthalten.
function inlineMd(line) {
  const out = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let last = 0, m;
  while ((m = re.exec(line))) {
    if (m.index > last) out.push(line.slice(last, m.index));
    const t = m[0];
    out.push(t.startsWith("**") ? h("strong", null, t.slice(2, -2)) : h("code", null, t.slice(1, -1)));
    last = m.index + t.length;
  }
  if (last < line.length) out.push(line.slice(last));
  return out;
}
function renderMd(text) {
  const out = [];
  let list = null, code = null;
  for (const raw of String(text).split("\n")) {
    const line = raw.replace(/\s+$/, "");
    if (line.trim().startsWith("```")) {
      if (code) { out.push(h("pre", { class: "plain mono" }, code.join("\n"))); code = null; } else { code = []; list = null; }
      continue;
    }
    if (code) { code.push(raw); continue; }
    const hd = line.match(/^#{1,4}\s+(.*)$/);
    const li = line.match(/^\s*(?:[-*•]|\d+[.)])\s+(.*)$/);
    if (hd) { list = null; out.push(h("h4", { class: "md-h" }, inlineMd(hd[1]))); continue; }
    if (li) {
      if (!list) { list = h("ul", { class: "plain" }); out.push(list); }
      list.append(h("li", null, inlineMd(li[1])));
      continue;
    }
    list = null;
    if (line.trim()) out.push(h("p", { class: "md-p" }, inlineMd(line)));
  }
  if (code) out.push(h("pre", { class: "plain mono" }, code.join("\n")));
  return h("div", { class: "md" }, out);
}

// reportCard lädt den Bericht nach, damit die Seite sofort erscheint.
export function reportCard({ ip, session }) {
  const body = h("div", null, h("p", { class: "muted" }, "Bericht wird erstellt …"));
  const box = card("Angriffsbericht", body);
  const query = ip ? "ip=" + encodeURIComponent(ip) : "session=" + encodeURIComponent(session);

  const aiBox = h("div");
  const showAI = (ai) => mount(aiBox, h("h3", null, "KI-Auswertung", ai.at ? h("span", { class: "muted" }, " · ", relTime(ai.at)) : null),
    renderMd(ai.text),
    h("p", { class: "muted" }, "Von einem Sprachmodell erzeugt; kann Fehler enthalten. Grundlage ist der Bericht oben."));

  api("report?" + query).then((d) => {
    const r = d.report;
    if (!r.events) { mount(body, h("div", { class: "empty" }, "Keine Ereignisse für einen Bericht.")); return; }
    const aiBtn = h("button", { class: "btn" }, d.ai ? "KI-Auswertung erneuern" : "KI-Auswertung anfordern");
    const aiMsg = h("span", { class: "muted" });
    aiBtn.addEventListener("click", async () => {
      aiBtn.disabled = true;
      aiMsg.textContent = "Das Modell arbeitet, das kann bei lokalen Modellen einige Minuten dauern …";
      try {
        showAI(await api("report/ai", { method: "POST", body: ip ? { ip } : { session } }));
        aiMsg.textContent = "";
        aiBtn.textContent = "KI-Auswertung erneuern";
      } catch (e) { aiMsg.textContent = "Fehler: " + e.message; }
      aiBtn.disabled = false;
    });
    mount(body,
      h("p", null, h("span", { class: "badge sev-" + r.severity }, SEV[r.severity] || r.severity)),
      h("ul", { class: "plain" }, r.summary.map((l) => h("li", null, l))),
      r.tags.length ? [h("h3", null, "Erkannte Muster"), h("ul", { class: "taglist" }, r.tags.map((t) => h("li", null,
        h("strong", null, t.name), " ", h("span", { class: "badge" }, fmtNum(t.n) + "×"),
        (t.mitre || []).map((m) => [" ", h("a", { class: "badge", href: "https://attack.mitre.org/techniques/" + m.replace(".", "/") + "/", target: "_blank", rel: "noopener noreferrer", title: "MITRE ATT&CK" }, m)]),
        h("div", { class: "desc" }, t.desc), h("code", null, t.example))))] : null,
      r.cves && r.cves.length ? [h("h3", null, "Bekannte Lücken (CVE)"), h("ul", { class: "plain" }, r.cves.map((c) => h("li", null,
        h("a", { class: "mono", href: "https://nvd.nist.gov/vuln/detail/" + c.key, target: "_blank", rel: "noopener noreferrer" }, c.key), " ", c.label, " ", h("span", { class: "badge" }, fmtNum(c.n) + "×"))))] : null,
      h("div", { class: "grid three" },
        r.tools.length ? h("div", null, h("h3", null, "Werkzeuge"), toplist(r.tools)) : null,
        r.creds.length ? h("div", null, h("h3", null, "Zugangsdaten"), toplist(r.creds.slice(0, 15))) : null,
        r.requests.length ? h("div", null, h("h3", null, "Anfragen"), toplist(r.requests.slice(0, 15))) : null),
      r.decoded && r.decoded.length ? [h("h3", null, "Entschlüsselte Inhalte (Base64, Hex, URL-Kodierung)"),
        h("p", { class: "muted", style: { margin: "0 0 6px" } }, "Der Angreifer hat diese Stellen verschleiert; so sehen sie im Klartext aus."),
        h("div", { class: "term" }, r.decoded.map((c) => h("div", null, c)))] : null,
      r.urls.length ? [h("h3", null, "Nachlade-Adressen (nicht aufrufen)"), monoList(r.urls.map((u) => [u, " ", lookupBtn("URLhaus", "lookup/urlhaus?url=" + encodeURIComponent(u), urlhausText)]))] : null,
      r.files.length ? [h("h3", null, "Dateien"), monoList(r.files)] : null,
      r.hashes.length ? [h("h3", null, "SHA-256 der Downloads"), monoList(r.hashes.map((x) => (sha256.test(x)
        ? [x, " ", h("a", { href: "https://www.virustotal.com/gui/file/" + x, target: "_blank", rel: "noopener noreferrer" }, "bei VirusTotal nachschlagen"), " ",
          lookupBtn("MalwareBazaar", "lookup/malwarebazaar?hash=" + x, bazaarText)] : x)))] : null,
      r.clients.length ? [h("h3", null, "Clients"), monoList(r.clients)] : null,
      r.commands.length ? [h("h3", null, "Befehle in Reihenfolge"), h("div", { class: "term" }, r.commands.map((c) => h("div", null, h("span", { class: "cmd" }, c))))] : null,
      h("div", { class: "btnrow" },
        h("a", { class: "btn", href: "api/report?" + query + "&format=text", download: "" }, "Als Text speichern"),
        state.user.role === "viewer" ? null
          : d.ai_enabled ? aiBtn : h("span", { class: "muted" }, "KI-Auswertung: unter Einstellungen einrichten (lokales Modell oder OpenRouter)."),
        aiMsg),
      aiBox);
    if (d.ai) showAI(d.ai);
  }).catch((e) => mount(body, h("div", { class: "msg err" }, "Bericht nicht verfügbar: " + e.message)));
  return box;
}

// ---------- Terminal-Mitschnitt (Cowrie) ----------

export function ttyCard(session) {
  const out = h("div", { class: "term tty", hidden: true });
  const info = h("span", { class: "muted" });
  let log = null, timer = null;
  const frame = (f) => h("span", { class: f.d === "in" ? "in" : "" }, f.s);
  const stop = () => { clearTimeout(timer); timer = null; playBtn.textContent = "Abspielen"; };
  const showAll = () => { stop(); mount(out, log.frames.map(frame)); };
  async function load() {
    if (log) return true;
    try {
      log = await api("sessions/" + encodeURIComponent(session) + "/tty");
    } catch (e) { info.textContent = e.message; return false; }
    out.hidden = false;
    playBtn.hidden = false;
    info.textContent = `${fmtNum(log.frames.length)} Abschnitte, ${fmtDur(log.duration_ms)}${log.truncated ? ", gekürzt" : ""}. Eingaben des Angreifers sind grün.`;
    return true;
  }
  const loadBtn = h("button", { class: "btn", onclick: async () => { if (await load()) showAll(); } }, "Mitschnitt anzeigen");
  const playBtn = h("button", {
    class: "btn", hidden: true,
    onclick: () => {
      if (timer) { showAll(); return; }
      mount(out);
      playBtn.textContent = "Alles zeigen";
      let i = 0;
      const step = () => {
        if (i >= log.frames.length || !out.isConnected) { stop(); return; }
        out.append(frame(log.frames[i]));
        out.scrollTop = out.scrollHeight;
        const gap = i + 1 < log.frames.length ? log.frames[i + 1].t - log.frames[i].t : 0;
        i++;
        timer = setTimeout(step, Math.min(1200, Math.max(30, gap / 2))); // doppelte Geschwindigkeit, Pausen gekappt
      };
      step();
    },
  }, "Abspielen");
  return card("Terminal-Mitschnitt",
    h("p", { class: "sub" }, "Was der Angreifer in der gefälschten Shell gesehen und getippt hat (aufgezeichnet von Cowrie)."),
    h("div", { class: "btnrow" }, loadBtn, playBtn, info), out);
}

// ---------- Abgleich mit Reputationsdiensten ----------

export function intelCard(ip) {
  const res = h("div");
  const ext = (label, href) => h("a", { class: "btn small", href, target: "_blank", rel: "noopener noreferrer" }, label);
  const enc = encodeURIComponent(ip);
  const check = h("button", {
    class: "btn",
    onclick: async () => {
      check.disabled = true;
      try {
        const r = await api("attackers/" + enc + "/intel");
        const d = r.data;
        const score = Number(d.abuseConfidenceScore) || 0;
        mount(res, h("table", null, h("tbody", null, [
          ["Missbrauchs-Wert", h("span", { class: "badge " + (score >= 50 ? "err" : score > 0 ? "" : "ok") }, score + " von 100")],
          ["Meldungen (90 Tage)", `${fmtNum(d.totalReports)} von ${fmtNum(d.numDistinctUsers)} Meldern`],
          ["Zuletzt gemeldet", d.lastReportedAt ? fmtDateTime(d.lastReportedAt) : "nie"],
          ["Art des Anschlusses", d.usageType || "–"], ["Anbieter", d.isp || "–"],
          ["Tor-Ausgang", d.isTor ? "ja" : "nein"],
          ["Stand", relTime(r.at) + (r.cached ? " (zwischengespeichert)" : "")],
        ].map(([k, v]) => h("tr", null, h("th", null, k), h("td", null, v))))));
      } catch (e) { mount(res, h("div", { class: "msg err" }, e.message)); }
      check.disabled = false;
    },
  }, "Bei AbuseIPDB abfragen");
  const gnRes = h("div");
  const gn = h("button", {
    class: "btn",
    onclick: async () => {
      gn.disabled = true;
      try {
        const r = await api("attackers/" + enc + "/greynoise");
        const d = r.data;
        const cls = { malicious: "bösartig", benign: "harmlos", unknown: "unbekannt" }[d.classification] || d.classification || "–";
        mount(gnRes, h("table", null, h("tbody", null, [
          ["Bekannter Massen-Scanner", d.noise ? h("span", { class: "badge err" }, "ja") : "nein"],
          ["Bekannter harmloser Dienst", d.riot ? h("span", { class: "badge ok" }, "ja") : "nein"],
          ["Einstufung", d.found ? cls : "GreyNoise kennt diese IP nicht"],
          d.name && d.name !== "unknown" ? ["Name", d.name] : null,
          d.last_seen ? ["Zuletzt gesehen", d.last_seen] : null,
          ["Stand", relTime(r.at) + (r.cached ? " (zwischengespeichert)" : "")],
        ].filter(Boolean).map(([k, v]) => h("tr", null, h("th", null, k), h("td", null, v))))));
      } catch (e) { mount(gnRes, h("div", { class: "msg err" }, e.message)); }
      gn.disabled = false;
    },
  }, "Bei GreyNoise abfragen");
  return card("Reputation",
    h("p", { class: "sub" }, "Die Abfragen schicken diese IP-Adresse an AbuseIPDB bzw. GreyNoise (nur auf Knopfdruck, Ergebnis 24 Stunden gespeichert). Die Links öffnen die Seite des jeweiligen Dienstes."),
    h("div", { class: "btnrow" }, check, gn,
      ext("AbuseIPDB", "https://www.abuseipdb.com/check/" + enc), ext("GreyNoise", "https://viz.greynoise.io/ip/" + enc),
      ext("Shodan", "https://www.shodan.io/host/" + enc), ext("VirusTotal", "https://www.virustotal.com/gui/ip-address/" + enc)),
    res, gnRes);
}

// ---------- Einstellungen der Zusatzfunktionen ----------

export async function extrasCards() {
  let d;
  try { d = await api("extras"); } catch (e) { return h("div", { class: "msg err" }, "Zusatz-Einstellungen nicht verfügbar: " + e.message); }
  const x = structuredClone(d.extras);
  const secrets = {}; // nur neu eingegebene Geheimnisse; leer = unverändert
  const msg = h("div", { class: "msg", hidden: true });
  const show = (text, ok) => { msg.className = "msg " + (ok ? "ok" : "err"); msg.textContent = text; msg.hidden = false; };
  const row = (label, input, help) => h("div", { class: "form-row" }, h("label", null, label), input, help ? h("div", { class: "help" }, help) : null);
  const text = (obj, key, attrs = {}) => h("input", { value: obj[key] ?? "", style: { width: "100%", maxWidth: "460px" }, ...attrs, onchange: (e) => { obj[key] = e.target.value.trim(); } });
  const numIn = (obj, key, min, max, step) => h("input", { type: "number", value: obj[key], min, max, step, style: { width: "120px" }, onchange: (e) => { obj[key] = Number(e.target.value); } });
  const check = (obj, key, label) => h("label", { class: "inline" }, h("input", { type: "checkbox", checked: !!obj[key], onchange: (e) => { obj[key] = e.target.checked; } }), label);
  const secret = (name) => h("input", {
    type: "password", autocomplete: "off", style: { width: "100%", maxWidth: "460px" },
    placeholder: d.secrets[name] ? "gespeichert – leer lassen zum Behalten, „-“ zum Löschen" : "nicht gesetzt",
    onchange: (e) => { secrets[name] = e.target.value; },
  });

  const body = () => ({
    home: x.home, abuseipdb_key: secrets.abuseipdb_key || "", greynoise_key: secrets.greynoise_key || "", abusech_key: secrets.abusech_key || "",
    notify: { ...x.notify, ntfy_token: secrets.ntfy_token || "", telegram_token: secrets.telegram_token || "" },
    ai: { ...x.ai, api_key: secrets.ai_api_key || "" },
    own: x.own, abuse_report: x.abuse_report,
  });
  async function save() {
    try {
      await api("extras", { method: "PUT", body: body() });
      show("Gespeichert.", true);
      return true;
    } catch (e) { show(e.message, false); return false; }
  }
  async function testNotify() {
    if (!(await save())) return;
    try {
      await api("extras/test-notify", { method: "POST" });
      show("Testnachricht gesendet.", true);
    } catch (e) { show("Senden fehlgeschlagen: " + e.message, false); }
  }

  const n = x.notify, st = d.notify_status || {};
  x.own = x.own || { private: true, nets: [], in_stats: false };
  x.abuse_report = x.abuse_report || { enabled: false, dry_run: true, daily_limit: 50, interval_hours: 24, skip_scanners: true };
  return h("div", { class: "stack" },
    card("Standort für die Karte",
      h("p", { class: "sub" }, "Dorthin zeigen die Angriffslinien auf der Karte. Ein ungefährer Ort genügt; er wird nirgends veröffentlicht."),
      row("Breite", numIn(x.home, "lat", -90, 90, 0.1), "Nordhalbkugel positiv, z. B. 52.5 für Berlin."),
      row("Länge", numIn(x.home, "lon", -180, 180, 0.1), "Östlich von Greenwich positiv, z. B. 13.4 für Berlin."),
      row("Bezeichnung", text(x.home, "label", { maxlength: 40 }))),
    card("Eigene Netze",
      h("p", { class: "sub" }, "Verbindungen von hier sind eigene Tests: Sie werden gespeichert und sind auf der Seite Angriffe über den Filter „Eigene Tests“ einsehbar, ",
        "zählen aber nicht in Kennzahlen, Top-Listen, „Gerade aktiv“ und Benachrichtigungen. Gilt ab dem Speichern."),
      row("Heimnetz", check(x.own, "private", "Private Adressen (192.168.x.x, 10.x.x.x, 172.16–31.x.x, fd00::/8 …) sind eigene Tests")),
      row("Weitere Netze", h("textarea", { rows: 3, style: { width: "100%", maxWidth: "460px" }, placeholder: "203.0.113.0/24\n198.51.100.7",
        onchange: (e) => { x.own.nets = e.target.value.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean); } }, (x.own.nets || []).join("\n")),
        "Eine Adresse oder ein Netz (CIDR) je Zeile, z. B. die feste IP deines Anschlusses, wenn du von außen testest."),
      row("Trotzdem zählen", check(x.own, "in_stats", "Eigene Tests in Kennzahlen und Benachrichtigungen mitzählen"))),
    card("Benachrichtigungen",
      h("p", { class: "sub" }, "Meldung aufs Handy, wenn etwas Wichtiges passiert. Je Angreifer und Anlass höchstens eine Meldung in 10 Minuten."),
      row("Aktiv", check(n, "enabled", "Benachrichtigungen senden")),
      row("ntfy-Adresse", text(n, "ntfy_url", { placeholder: "https://ntfy.sh/mein-geheimes-thema" }), "Vollständige Adresse des Themas. Bei ntfy.sh ist der Themenname das einzige Geheimnis: lang und zufällig wählen."),
      row("ntfy-Token", secret("ntfy_token"), "Nur für geschützte Themen oder einen eigenen ntfy-Server."),
      row("Telegram-Bot-Token", secret("telegram_token"), "Vom BotFather."),
      row("Telegram-Chat-ID", text(n, "telegram_chat", { maxlength: 64 })),
      row("Webhook-Adresse", text(n, "webhook_url", { placeholder: "https://…" }), "Bekommt JSON mit title, text, kind, ip und time (z. B. für Home Assistant)."),
      row("Anlässe", h("div", null,
        check(n, "on_login", "Erfolgreicher Login (Cowrie)"), h("br"),
        check(n, "on_download", "Datei geladen"), h("br"),
        check(n, "on_severe", "Schweres Angriffsmuster (Nachladen, Miner, Übernahme)"), h("br"),
        check(n, "on_command", "Erster Befehl einer Sitzung"), h("br"),
        check(n, "on_warning", "Kritische Systemwarnung (Sensor still, Netzsperre fehlt)"), h("br"),
        check(n, "weekly_report", "Wochenbericht (montags ab 8 Uhr)"))),
      h("details", null, h("summary", null, "Vorschau des Wochenberichts (letzte 7 Tage)"), weeklyBox()),
      row("Höchstens pro Stunde", numIn(n, "max_per_hour", 1, 500, 1), "Darüber wird nur gezählt."),
      h("p", { class: "muted" }, `Bisher gesendet: ${fmtNum(st.sent)}, unterdrückt: ${fmtNum(st.suppressed)}.`,
        st.last_error ? h("span", { class: "warn-text" }, " Letzter Fehler: " + st.last_error) : null),
      h("div", { class: "btnrow" }, h("button", { class: "btn", onclick: testNotify }, "Speichern und Testnachricht senden"))),
    card("KI-Auswertung (optional)",
      h("p", { class: "sub" }, "Lässt einen Angriffsbericht von einem Sprachmodell in Worte fassen, auf Knopfdruck im Bericht. ",
        "Funktioniert mit jeder OpenAI-kompatiblen Schnittstelle: lokal mit Ollama oder LM Studio, oder über einen Dienst wie OpenRouter."),
      h("div", { class: "msg warn" }, "Datenschutz: Bei einem Dienst im Internet verlassen IP-Adressen, Zugangsdaten und Befehle der Angreifer dein Netz. Mit einem lokalen Modell bleibt alles im Haus."),
      row("Aktiv", check(x.ai, "enabled", "KI-Auswertung anbieten")),
      row("Adresse", text(x.ai, "base_url", { placeholder: "http://192.168.1.10:11434/v1" }), "Ollama: http://<Rechner>:11434/v1 · OpenRouter: https://openrouter.ai/api/v1"),
      row("Modell", text(x.ai, "model", { placeholder: "llama3.1:8b" }), "Name, wie ihn die Schnittstelle erwartet, z. B. llama3.1:8b; bei OpenRouter der dort angezeigte Modellname."),
      row("API-Schlüssel", secret("ai_api_key"), "Für lokale Modelle meist leer.")),
    card("AbuseIPDB (optional)",
      h("p", { class: "sub" }, "Mit einem kostenlosen Schlüssel von abuseipdb.com lässt sich auf der Seite eines Angreifers nachsehen, wie oft seine IP weltweit gemeldet wurde."),
      row("API-Schlüssel", secret("abuseipdb_key")),
      h("h3", null, "Angreifer automatisch melden"),
      h("p", { class: "sub" }, "Meldet echte Angriffsversuche (Login-Versuche, Exploits, Befehle, Downloads) an AbuseIPDB, damit andere sie blockieren können. ",
        "Nie gemeldet werden eigene und private Adressen, Angriffe nur über UDP (Absender fälschbar) und reines Abtasten. ",
        "Der Kommentar enthält keine Passwörter, keine IP-Adressen und keine Hostnamen des Honeypots."),
      row("Aktiv", check(x.abuse_report, "enabled", "Automatisch melden")),
      row("Probemodus", check(x.abuse_report, "dry_run", "Nur protokollieren, was gemeldet würde (nichts senden)"), "Zum Ausprobieren: erst eine Weile im Probemodus laufen lassen und das Protokoll unten ansehen."),
      row("Höchstens pro Tag", numIn(x.abuse_report, "daily_limit", 1, 1000, 1), "Das kostenlose Kontingent von AbuseIPDB liegt bei 1.000 Meldungen am Tag."),
      row("Abstand je IP (Stunden)", numIn(x.abuse_report, "interval_hours", 1, 720, 1), "AbuseIPDB nimmt dieselbe IP höchstens alle 15 Minuten an."),
      row("Ausnahmen", h("div", null,
        check(x.abuse_report, "skip_scanners", "Forschungsscanner (Shodan, Censys, Shadowserver …) nicht melden"), h("br"),
        check(x.abuse_report, "include_web_probe", "Auch die Suche nach .env, .git und Anmeldeseiten als Web-Angriff melden"))),
      await abuseLogBox()),
    card("URLhaus und MalwareBazaar (optional)",
      h("p", { class: "sub" }, "Mit einem kostenlosen Schlüssel von auth.abuse.ch lassen sich im Angriffsbericht Nachlade-Adressen bei URLhaus und Datei-Hashes bei MalwareBazaar nachschlagen, ",
        "jeweils nur auf Knopfdruck. Es wird nichts hochgeladen; abuse.ch sieht nur die abgefragte Adresse bzw. den Hash."),
      row("Auth-Key", secret("abusech_key"))),
    card("GreyNoise (optional)",
      h("p", { class: "sub" }, "Zeigt, ob eine IP als Massen-Scanner oder als harmloser Dienst (z. B. Suchmaschine) bekannt ist. Geht ohne Schlüssel mit kleinem Tageskontingent; ein kostenloser Schlüssel von greynoise.io erhöht es."),
      row("API-Schlüssel", secret("greynoise_key"))),
    h("div", null, h("button", { class: "btn primary", onclick: async () => { if (await save()) homeCache = null; } }, "Zusatzfunktionen speichern"), msg),
    await usersCard());
}

// Protokoll der AbuseIPDB-Meldungen (auch Probemodus), Kontingent und letzter Fehler
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

// ---------- Benutzer (nur für Admins) ----------

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
  const role = h("select", null, h("option", { value: "viewer" }, "Nur ansehen"), h("option", { value: "admin" }, "Admin"));
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
    h("p", { class: "sub" }, "Weitere Konten für die Web-UI. „Nur ansehen“ sieht alle Auswertungen, kann aber nichts ändern und keine KI-Auswertung starten."),
    h("div", { class: "tablewrap" }, h("table", null, h("thead", null, h("tr", null, h("th", null, "Name"), h("th", null, "Rolle"), h("th", null, ""))), body)),
    add, msg);
}
