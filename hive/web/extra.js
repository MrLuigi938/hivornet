// Zusatzfunktionen der UI: Live-Karte, Analyse, Angriffsbericht mit KI-Auswertung,
// Terminal-Mitschnitt und AbuseIPDB-Abgleich. Die Einstellungen dazu stehen in settings.js.
//
// Wie überall gilt: Angreiferdaten werden nur als Text eingefügt (h() aus dom.js).
// Adressen aus Angreiferdaten werden nie zu Links gemacht.
import { h, s, mount, api, fmtNum, fmtDur, fmtTime, fmtDateTime, relTime, flag } from "./dom.js";
import { worldMap, toplist, svcName, countryName } from "./charts.js";
import { state, header, card, tile, cc, ipLink, svcBadge, describe, isNoise, TYPE_NAME } from "./app.js";
import { aiReplies, exploitHits } from "./attacks.js";

// ---------- Standort des Honeypots (Ziel der Angriffslinien) ----------

let homeCache = null;
export async function homeLocation() {
  if (!homeCache) {
    try { homeCache = (await api("extras")).extras.home; } catch { homeCache = null; }
  }
  return homeCache || { lat: 51.1, lon: 10.4, label: "Honeypot" };
}
// Nach dem Speichern des Standorts (Einstellungen) neu laden
export function forgetHome() { homeCache = null; }

// ---------- Live-Karte ----------

export async function viewLive(el, ctx) {
  header("Live-Karte");
  const [mp, ctry, home] = await Promise.all([api("stats/map?range=24h"), api("stats/top?field=country&limit=100&range=24h"), homeLocation()]);
  const map = worldMap(mp, { home, large: true, countries: ctry });
  api("attacks?active=1&limit=200").then((d) => map.seedActive(d.attacks)).catch(() => {}); // Linien der letzten 10 Minuten
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
      home.label || "Honeypot", "). Sie bleibt stehen, bis er 10 Minuten lang nichts mehr getan hat. ",
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
// MITRE-Link: ATT&CK (T1234.001) oder ATLAS für KI-Angriffe (AML.T0051)
const mitreURL = (m) => (m.startsWith("AML.") ? "https://atlas.mitre.org/techniques/" + m : "https://attack.mitre.org/techniques/" + m.replace(".", "/") + "/");

// Statische Auswertung einer nachgeladenen Datei auf dem Gerät (hive/sample.go); nichts wird ausgeführt.
function sampleBtn(hash) {
  const out = h("div", { class: "aw-note", hidden: true });
  const b = h("button", { class: "btn small", onclick: async () => {
    b.disabled = true;
    out.hidden = false;
    mount(out, h("span", { class: "muted" }, "untersuche …"));
    try {
      const d = await api("sample?hash=" + hash);
      const facts = [
        ["Typ", [d.type, d.arch ? `${d.arch}, ${d.bits} Bit, ${d.endian}` : "", d.static ? "statisch gelinkt" : "", d.packed ? "gepackt mit " + d.packed : ""].filter(Boolean).join(" · ")],
        ["Größe", fmtNum(d.size) + " Bytes" + (d.truncated ? " (nur die ersten 16 MB untersucht)" : "")],
        d.interpreter ? ["Erste Zeile", d.interpreter] : null,
        d.patterns?.length ? ["Muster", d.patterns.map((p) => `${p.label} (${fmtNum(p.n)})`).join(", ")] : null,
        d.urls?.length ? ["Adressen", d.urls.join("  ·  ")] : null,
        d.ips?.length ? ["IPs", d.ips.join(", ")] : null,
        d.wallets?.length ? ["Wallets", d.wallets.join(", ")] : null,
        d.pools?.length ? ["Mining-Pools", d.pools.join(", ")] : null,
        ["Zeichenketten", fmtNum(d.strings)],
      ].filter(Boolean);
      mount(out, h("div", { class: "facts-row" }, facts.map(([k, v]) => [h("div", { class: "k" }, k), h("div", { class: "v mono" }, v)])),
        d.hash_mismatch ? h("div", { class: "msg warn" }, "Der Inhalt passt nicht zum Hash im Dateinamen.") : null,
        h("p", { class: "muted aw-small" }, "Nur gelesen, nie ausgeführt. Die Datei liegt weiter im Cowrie-Ordner und ist echte Schadsoftware."));
    } catch (e) { mount(out, h("span", { class: "muted" }, e.message)); }
    b.disabled = false;
  } }, "Datei untersuchen");
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
// Frei beweglicher Graph: Bubbles (Ports, Anmeldungen, Exploits, Befehlsgruppen, Nachlade-
// Hosts, Dateien, Weiterleitungen) mit Pfeilen für die Reihenfolge je Sitzung und die
// Herkunft von Dateien. Eine kleine Kräfte-Simulation ordnet sie an; jede Bubble zieht es
// in das Band ihrer Phase (Erkundung → … → Ziel), damit die Richtung lesbar bleibt.
// Verschieben, Zoomen und Umsetzen mit Maus, Touch oder Knöpfen. Klick zeigt Einzelheiten.
// Angreiferdaten nur als Textknoten (s()/h()).
const KIND_NAME = { service: "Dienst", login: "Anmeldeversuche", login_ok: "Login angenommen", exploit: "Exploit", pattern: "Muster",
  commands: "Befehle", host: "Nachlade-Host", file: "Datei", forward: "Weiterleitung", prompt: "Login-Abfrage", web: "Web-Anfragen", ai: "Antwort der KI", more: "Sammelknoten" };
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

// chainCard liefert die Karte; card.refresh() lädt die Kette neu und tauscht sie unauffällig aus:
// bekannte Bubbles behalten Platz, Zoom und Auswahl, nur neue kommen hinzu (Seite eines Angreifers live).
export function chainCard({ ip, session }) {
  const box = h("div", null, h("p", { class: "muted" }, "Lade Angriffskette …"));
  const query = ip ? "ip=" + encodeURIComponent(ip) : "session=" + encodeURIComponent(session);
  let cur = null, sig = "", busy = false;
  const signature = (c) => JSON.stringify([c.events, c.nodes.map((n) => [n.id, n.n]), c.edges.map((e) => [e.from, e.to, e.n])]);
  api("chain?" + query).then((c) => { sig = signature(c); cur = chainView(c); mount(box, cur); })
    .catch((e) => mount(box, h("div", { class: "msg err" }, "Angriffskette nicht verfügbar: " + e.message)));
  const el = card("Angriffskette", box);
  el.refresh = async () => {
    if (busy || !cur || !box.isConnected) return;
    busy = true;
    try {
      const c = await api("chain?" + query);
      const s2 = signature(c);
      if (s2 !== sig) {
        sig = s2;
        const next = chainView(c, cur.chainState());
        cur.replaceWith(next);
        cur = next;
      }
    } catch { /* nächster Versuch */ }
    busy = false;
  };
  return el;
}

function chainView(c, prev = null) {
  if (!c.nodes.length) return h("div", { class: "empty" }, "Keine Ereignisse.");
  // ---- Modell: Knoten mit Position und Geschwindigkeit ----
  const PH = 260; // Abstand der Phasen-Bänder (Weltkoordinaten)
  const maxN = Math.max(1, ...c.nodes.map((n) => n.n));
  const nodes = c.nodes.map((n, i) => {
    const p = prev && prev.pos.get(n.id); // bekannte Bubble: Platz behalten
    return {
      ...n, r: 20 + 16 * Math.log1p(n.n) / Math.log1p(maxN), known: !!p, pinned: p ? p.fixed : false,
      x: p ? p.x : n.phase * PH + (Math.random() - 0.5) * 60, y: p ? p.y : ((i % 7) - 3) * 55 + (Math.random() - 0.5) * 30,
      vx: 0, vy: 0, fixed: p ? p.fixed : false,
    };
  });
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const edges = c.edges.filter((e) => byId.has(e.from) && byId.has(e.to)).map((e) => ({ ...e, a: byId.get(e.from), b: byId.get(e.to) }));
  const maxE = Math.max(1, ...edges.map((e) => e.n));

  // ---- Kräfte: Abstoßung, Federn an Kanten, Zug zum eigenen Phasen-Band, keine Überlappung ----
  let alpha = 1, raf = 0;
  function tick() {
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        let dx = b.x - a.x, dy = b.y - a.y, d2 = dx * dx + dy * dy || 0.01;
        const d = Math.sqrt(d2), min = a.r + b.r + 48; // Platz für die Beschriftung
        let f = 5200 / d2; // Abstoßung
        if (d < min) f += (min - d) * 0.5; // Überlappung auflösen
        dx /= d; dy /= d;
        a.vx -= dx * f; a.vy -= dy * f; b.vx += dx * f; b.vy += dy * f;
      }
    }
    for (const e of edges) { // Federn
      const dx = e.b.x - e.a.x, dy = e.b.y - e.a.y, d = Math.hypot(dx, dy) || 0.01;
      const f = (d - 150) * 0.012;
      e.a.vx += (dx / d) * f; e.a.vy += (dy / d) * f; e.b.vx -= (dx / d) * f; e.b.vy -= (dy / d) * f;
    }
    for (const n of nodes) {
      n.vx += (n.phase * PH - n.x) * 0.045; // Phase: links nach rechts
      n.vy += -n.y * 0.004;
      if (n.fixed) { n.vx = n.vy = 0; continue; }
      n.x += Math.max(-40, Math.min(40, n.vx * alpha));
      n.y += Math.max(-40, Math.min(40, n.vy * alpha));
      n.vx *= 0.55; n.vy *= 0.55;
    }
  }
  function run(steps = 1) {
    alpha = Math.max(alpha, 0.3);
    cancelAnimationFrame(raf);
    const loop = () => {
      for (let i = 0; i < steps; i++) tick();
      alpha *= 0.985;
      draw();
      if (alpha > 0.02 && svg.isConnected !== false) raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
  }
  // Vorlauf ohne Zeichnen, damit die Ansicht ruhig startet. Bei einer Aktualisierung bleiben die
  // bekannten Bubbles stehen; nur neue suchen sich ihren Platz.
  if (prev) {
    nodes.forEach((n) => { if (n.known) n.fixed = true; });
    for (let i = 0; i < 160; i++) { tick(); alpha = Math.max(0.05, alpha * 0.99); }
    nodes.forEach((n) => { if (n.known) n.fixed = n.pinned; });
  } else {
    for (let i = 0; i < 260; i++) { tick(); alpha = Math.max(0.05, alpha * 0.99); }
  }

  // ---- Zeichnen ----
  const view = prev ? { ...prev.view } : { k: 1, x: 0, y: 0 }; // Verschiebung und Zoom (bei Aktualisierung übernommen)
  const world = s("g", { class: "cg-world" });
  const bands = s("g");
  c.phases.forEach((p, i) => bands.append(
    s("rect", { class: "cg-band" + (i % 2 ? " alt" : ""), x: i * PH - PH / 2, y: -5000, width: PH, height: 10000 }),
    s("text", { class: "cg-phase", x: i * PH, "text-anchor": "middle", "data-phase": i }, `${i + 1}. ${p}`)));
  const edgeG = s("g"), nodeG = s("g");
  world.append(bands, edgeG, nodeG);
  const edgeEls = edges.map((e) => {
    const w = 1.2 + 3 * Math.log1p(e.n) / Math.log1p(maxE);
    const p = s("path", { class: "cg-edge" + (e.b.kind === "ai" ? " ai" : e.label ? " flow" : ""), "stroke-width": w.toFixed(2), "marker-end": "url(#cg-arrow)" },
      s("title", null, `${e.a.label} → ${e.b.label}${e.label ? " (" + e.label + ")" : ""}: ${e.n}×`));
    edgeG.append(p);
    return p;
  });
  const nodeEls = nodes.map((n) => {
    const g = s("g", { class: "cg-node sev" + Math.min(4, n.sev) + " kind-" + n.kind, tabindex: 0, role: "button", "aria-label": n.label },
      s("title", null, `${n.label}${n.sub ? " – " + n.sub : ""} (${n.n}×, ${c.phases[n.phase]})`),
      s("circle", { class: "cg-halo", r: n.r + 6 }),
      prev && !n.known ? s("circle", { class: "cg-new", r: n.r + 10 }) : null,
      s("circle", { class: "cg-bubble", r: n.r }),
      s("text", { class: "cg-count", "text-anchor": "middle", dy: "0.35em" }, n.n > 1 ? fmtNum(n.n) : "1"),
      s("text", { class: "cg-label", "text-anchor": "middle", y: n.r + 15 }, short(n.label, 26)),
      n.sub ? s("text", { class: "cg-sub", "text-anchor": "middle", y: n.r + 29 }, short(n.sub, 30)) : null);
    if (n.fixed) g.classList.add("pinned");
    nodeG.append(g);
    n.el = g;
    return g;
  });
  const svg = s("svg", { class: "cg-svg", role: "img", "aria-label": "Angriffskette als frei beweglicher Graph" },
    s("defs", null, s("marker", { id: "cg-arrow", viewBox: "0 0 10 10", refX: "9", refY: "5", markerWidth: "6", markerHeight: "6", orient: "auto-start-reverse" },
      s("path", { d: "M0,0 L10,5 L0,10 z", class: "cg-arrowhead" }))),
    world);

  function draw() {
    world.setAttribute("transform", `translate(${view.x},${view.y}) scale(${view.k})`);
    const top = Math.min(...nodes.map((n) => n.y - n.r)) - 46;
    bands.querySelectorAll(".cg-phase").forEach((t) => t.setAttribute("y", top));
    edges.forEach((e, i) => {
      const dx = e.b.x - e.a.x, dy = e.b.y - e.a.y, d = Math.hypot(dx, dy) || 1;
      const x1 = e.a.x + (dx / d) * e.a.r, y1 = e.a.y + (dy / d) * e.a.r;
      const x2 = e.b.x - (dx / d) * (e.b.r + 5), y2 = e.b.y - (dy / d) * (e.b.r + 5);
      const bend = 0.18 * d, mx = (x1 + x2) / 2 - (dy / d) * bend * 0.3, my = (y1 + y2) / 2 + (dx / d) * bend * 0.3; // leichte Kurve
      edgeEls[i].setAttribute("d", `M${x1.toFixed(1)},${y1.toFixed(1)} Q${mx.toFixed(1)},${my.toFixed(1)} ${x2.toFixed(1)},${y2.toFixed(1)}`);
    });
    nodes.forEach((n) => n.el.setAttribute("transform", `translate(${n.x.toFixed(1)},${n.y.toFixed(1)})`));
  }
  function fit() {
    const r = svg.getBoundingClientRect();
    if (!r.width) return;
    const xs = nodes.map((n) => n.x), ys = nodes.map((n) => n.y);
    const x0 = Math.min(...xs) - 90, x1 = Math.max(...xs) + 90, y0 = Math.min(...ys) - 80, y1 = Math.max(...ys) + 70;
    view.k = Math.max(0.25, Math.min(1.4, Math.min(r.width / (x1 - x0), r.height / (y1 - y0))));
    view.x = (r.width - (x1 + x0) * view.k) / 2;
    view.y = (r.height - (y1 + y0) * view.k) / 2;
    draw();
  }
  const zoomAt = (f, cx, cy) => {
    const k = Math.max(0.2, Math.min(3, view.k * f));
    view.x = cx - (cx - view.x) * (k / view.k); view.y = cy - (cy - view.y) * (k / view.k); view.k = k;
    draw();
  };

  // ---- Bedienung: Hintergrund ziehen = verschieben, Mausrad = zoomen, Bubble ziehen = umsetzen ----
  let drag = null;
  svg.addEventListener("pointerdown", (ev) => {
    const g = ev.target.closest(".cg-node");
    const n = g && nodes.find((x) => x.el === g);
    drag = { n, sx: ev.clientX, sy: ev.clientY, vx: view.x, vy: view.y, moved: false };
    svg.setPointerCapture(ev.pointerId);
    svg.classList.add("dragging");
  });
  svg.addEventListener("pointermove", (ev) => {
    if (!drag) return;
    const dx = ev.clientX - drag.sx, dy = ev.clientY - drag.sy;
    if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
    if (drag.n) {
      const r = svg.getBoundingClientRect();
      drag.n.x = (ev.clientX - r.left - view.x) / view.k; drag.n.y = (ev.clientY - r.top - view.y) / view.k;
      drag.n.fixed = true; drag.n.el.classList.add("pinned");
      run();
    } else { view.x = drag.vx + dx; view.y = drag.vy + dy; draw(); }
  });
  svg.addEventListener("pointerup", () => {
    if (drag && drag.n && !drag.moved) select(drag.n.id);
    drag = null;
    svg.classList.remove("dragging");
  });
  svg.addEventListener("dblclick", (ev) => { // festgehaltene Bubble wieder freigeben
    const g = ev.target.closest(".cg-node");
    const n = g && nodes.find((x) => x.el === g);
    if (n) { n.fixed = false; g.classList.remove("pinned"); run(); }
  });
  svg.addEventListener("wheel", (ev) => {
    ev.preventDefault();
    const r = svg.getBoundingClientRect();
    zoomAt(ev.deltaY < 0 ? 1.12 : 1 / 1.12, ev.clientX - r.left, ev.clientY - r.top);
  }, { passive: false });
  nodeEls.forEach((g, i) => g.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); select(nodes[i].id); } }));

  // ---- Auswahl und Einzelheiten ----
  const detail = h("div", { class: "ch-detail" }, h("p", { class: "muted" }, "Eine Bubble anklicken, um Einzelheiten und Verbindungen zu sehen."));
  let selected = null;
  function select(id) {
    selected = selected === id ? null : id;
    svg.classList.toggle("focus", !!selected);
    const linked = new Set([selected]);
    edges.forEach((e, i) => {
      const on = !!selected && (e.from === selected || e.to === selected);
      edgeEls[i].classList.toggle("on", on);
      if (on) { linked.add(e.from); linked.add(e.to); }
    });
    nodes.forEach((n) => { n.el.classList.toggle("on", n.id === selected); n.el.classList.toggle("near", !!selected && linked.has(n.id)); });
    if (!selected) { mount(detail, h("p", { class: "muted" }, "Eine Bubble anklicken, um Einzelheiten und Verbindungen zu sehen.")); return; }
    const n = byId.get(selected);
    const ins = edges.filter((e) => e.to === n.id), outs = edges.filter((e) => e.from === n.id);
    const link = (id, extra) => h("button", { class: "linklike", onclick: () => select(id) }, byId.get(id).label, extra ? h("span", { class: "muted" }, " " + extra) : null);
    mount(detail,
      h("div", { class: "ch-dhead" }, h("span", { class: "badge stufe", style: { "--c": `var(--sev${Math.min(4, n.sev)})` } }, c.phases[n.phase]),
        h("strong", null, n.label), n.sub ? h("span", { class: "mono muted" }, n.sub) : null, h("span", { class: "badge" }, fmtNum(n.n) + "×")),
      h("p", { class: "muted" }, `${KIND_NAME[n.kind] || n.kind} · ${fmtDateTime(n.first)}` + (n.last > n.first ? ` bis ${fmtDateTime(n.last)}` : "")),
      n.mitre && n.mitre.length ? h("p", null, "MITRE ATT&CK: ", n.mitre.map((m) => [h("a", { class: "badge", href: mitreURL(m), target: "_blank", rel: "noopener noreferrer" }, m), " "])) : null,
      n.kind === "exploit" && /^CVE-/.test(n.label) ? h("p", null, h("a", { href: "https://nvd.nist.gov/vuln/detail/" + n.label, target: "_blank", rel: "noopener noreferrer" }, n.label + " in der NVD")) : null,
      h("div", { class: "grid two" },
        h("div", null, h("h3", null, "Folgte auf"), ins.length ? h("ul", { class: "plain" }, ins.map((e) => h("li", null, link(e.from, `${e.label ? e.label + ", " : ""}${e.n}×`)))) : h("p", { class: "muted" }, "Beginn")),
        h("div", null, h("h3", null, "Führte zu"), outs.length ? h("ul", { class: "plain" }, outs.map((e) => h("li", null, link(e.to, `${e.label ? e.label + ", " : ""}${e.n}×`)))) : h("p", { class: "muted" }, "Ende"))),
      n.examples && n.examples.length ? [h("h3", null, n.kind === "host" ? "Adressen (nicht aufrufen)" : "Beispiele"), h("div", { class: "term" }, n.examples.map((x) => h("div", null, x)))] : null);
  }

  const path = mainPath(c);
  const reached = Math.max(...c.nodes.map((n) => n.phase));
  const btn = (label, title, fn) => h("button", { class: "btn small", title, onclick: fn }, label);
  const tools = h("div", { class: "cg-tools" },
    btn("+", "Vergrößern", () => { const r = svg.getBoundingClientRect(); zoomAt(1.25, r.width / 2, r.height / 2); }),
    btn("−", "Verkleinern", () => { const r = svg.getBoundingClientRect(); zoomAt(0.8, r.width / 2, r.height / 2); }),
    btn("Einpassen", "Alles zeigen", fit),
    btn("Neu anordnen", "Festgehaltene Bubbles freigeben und neu anordnen", () => {
      nodes.forEach((n) => { n.fixed = false; n.el.classList.remove("pinned"); });
      alpha = 1; run(2); setTimeout(fit, 900);
    }));
  const stage = h("div", { class: "cg-stage" }, svg, tools);
  // erst einpassen, wenn die Fläche im Dokument ist und eine Größe hat (nicht bei einer Aktualisierung)
  if (!prev) {
    const ro = new ResizeObserver(() => { if (svg.getBoundingClientRect().width) { fit(); ro.disconnect(); } });
    ro.observe(stage);
  }
  draw();
  if (prev && prev.selected && byId.has(prev.selected)) select(prev.selected);
  const root = h("div", null,
    h("p", { class: "sub" }, `${fmtNum(c.events)} Ereignisse in ${fmtNum(c.sessions)} Sitzungen; erreicht bis Phase ${reached + 1} (${c.phases[reached]}).`,
      c.truncated ? " Nur die neuesten 5.000 Ereignisse." : ""),
    path.length > 1 ? h("div", { class: "ch-path" }, h("span", { class: "muted" }, "Hauptpfad: "),
      path.map((n, i) => [i ? h("span", { class: "ch-sep" }, " → ") : null, h("button", { class: "linklike", onclick: () => select(n.id) }, n.label)])) : null,
    stage,
    h("div", { class: "ch-legend muted" }, "Ziehen verschiebt die Ansicht, Mausrad zoomt; Bubbles lassen sich umsetzen (Doppelklick gibt sie frei). ",
      "Größe = Häufigkeit, Farbe = Schwere ", [0, 1, 2, 3, 4].map((i) => h("i", { class: "ch-dot", style: { background: `var(--sev${i})` } })),
      ", orange gestrichelt = Herkunft einer Datei bzw. Adresse, violett gepunktet = Antwort der KI."),
    detail);
  root.chainState = () => ({ pos: new Map(nodes.map((n) => [n.id, { x: n.x, y: n.y, fixed: n.fixed }])), view: { ...view }, selected });
  return root;
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
        (t.mitre || []).map((m) => [" ", h("a", { class: "badge", href: mitreURL(m), target: "_blank", rel: "noopener noreferrer", title: "MITRE ATT&CK" }, m)]),
        h("div", { class: "desc" }, t.desc), h("code", null, t.example))))] : null,
      r.rules && r.rules.length ? [h("h3", null, "Produkte und Lücken"),
        h("p", { class: "muted", style: { margin: "0 0 6px" } }, "Welche Software die Anfragen suchen (Probe) oder angreifen (Ausnutzung), mit CVE, CVSS, EPSS und Eintrag im CISA-Katalog der ausgenutzten Lücken (KEV). Ein Treffer heißt: versucht, nicht: verwundbar."),
        exploitHits(r.rules)] :
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
          lookupBtn("MalwareBazaar", "lookup/malwarebazaar?hash=" + x, bazaarText), " ", sampleBtn(x)] : x)))] : null,
      r.clients.length ? [h("h3", null, "Clients"), monoList(r.clients)] : null,
      r.commands.length ? [h("h3", null, "Befehle in Reihenfolge"), h("div", { class: "term" }, r.commands.map((c) => h("div", null, h("span", { class: "cmd" }, c))))] : null,
      r.ai_replies && r.ai_replies.length ? [h("h3", null, "Antworten der KI (" + fmtNum(r.ai_replies.length) + ")"),
        h("p", { class: "muted", style: { margin: "0 0 6px" } }, "Für diese Eingaben kannte der Honeypot keine feste Antwort; das Sprachmodell hat einen passenden Text erzeugt, der Honeypot hat ihn ausgeliefert. Ausgeführt wurde nichts."),
        aiReplies(r.ai_replies, { max: 5 })] : null,
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
