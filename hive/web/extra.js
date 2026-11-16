// Zusatzfunktionen der UI: Live-Karte, Analyse, Angriffsbericht mit KI-Auswertung,
// Terminal-Mitschnitt, AbuseIPDB-Abgleich und die Einstellungen dazu.
//
// Wie überall gilt: Angreiferdaten werden nur als Text eingefügt (h() aus dom.js).
// Adressen aus Angreiferdaten werden nie zu Links gemacht.
import { h, mount, api, fmtNum, fmtDur, fmtTime, fmtDateTime, relTime, flag } from "./dom.js";
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
  const [tags, tools, urls, clients, uas] = await Promise.all([q("tag"), q("tool", 60), q("url"), q("client", 15), q("useragent", 15)]);
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
    h("p", { class: "muted" }, "Den vollständigen Ablauf eines einzelnen Angreifers zeigt der Angriffsbericht auf der Seite der jeweiligen IP oder Sitzung.")));
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
        h("div", { class: "desc" }, t.desc), h("code", null, t.example))))] : null,
      h("div", { class: "grid three" },
        r.tools.length ? h("div", null, h("h3", null, "Werkzeuge"), toplist(r.tools)) : null,
        r.creds.length ? h("div", null, h("h3", null, "Zugangsdaten"), toplist(r.creds.slice(0, 15))) : null,
        r.requests.length ? h("div", null, h("h3", null, "Anfragen"), toplist(r.requests.slice(0, 15))) : null),
      r.decoded && r.decoded.length ? [h("h3", null, "Entschlüsselte Inhalte (Base64, Hex, URL-Kodierung)"),
        h("p", { class: "muted", style: { margin: "0 0 6px" } }, "Der Angreifer hat diese Stellen verschleiert; so sehen sie im Klartext aus."),
        h("div", { class: "term" }, r.decoded.map((c) => h("div", null, c)))] : null,
      r.urls.length ? [h("h3", null, "Nachlade-Adressen (nicht aufrufen)"), monoList(r.urls)] : null,
      r.files.length ? [h("h3", null, "Dateien"), monoList(r.files)] : null,
      r.hashes.length ? [h("h3", null, "SHA-256 der Downloads"), monoList(r.hashes.map((x) => (sha256.test(x)
        ? [x, " ", h("a", { href: "https://www.virustotal.com/gui/file/" + x, target: "_blank", rel: "noopener noreferrer" }, "bei VirusTotal nachschlagen")] : x)))] : null,
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
    home: x.home, abuseipdb_key: secrets.abuseipdb_key || "", greynoise_key: secrets.greynoise_key || "",
    notify: { ...x.notify, ntfy_token: secrets.ntfy_token || "", telegram_token: secrets.telegram_token || "" },
    ai: { ...x.ai, api_key: secrets.ai_api_key || "" },
    own: x.own,
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
        check(n, "on_warning", "Kritische Systemwarnung (Sensor still, Netzsperre fehlt)"))),
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
      row("API-Schlüssel", secret("abuseipdb_key"))),
    card("GreyNoise (optional)",
      h("p", { class: "sub" }, "Zeigt, ob eine IP als Massen-Scanner oder als harmloser Dienst (z. B. Suchmaschine) bekannt ist. Geht ohne Schlüssel mit kleinem Tageskontingent; ein kostenloser Schlüssel von greynoise.io erhöht es."),
      row("API-Schlüssel", secret("greynoise_key"))),
    h("div", null, h("button", { class: "btn primary", onclick: async () => { if (await save()) homeCache = null; } }, "Zusatzfunktionen speichern"), msg),
    await usersCard());
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
