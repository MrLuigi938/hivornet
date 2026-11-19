// KI-Bausteine der UI (hive/aiplus.go): KI-Wochenbericht, Kurzanalysen schwerer Angriffe,
// Suche in Alltagssprache, Skripte erklären, dazu die einfache Markdown-Darstellung der
// KI-Antworten (auch für die KI-Auswertung im Angriffsbericht).
//
// KI-Antworten können Angreifertext enthalten: nur Textknoten (h()), nie HTML, keine Links.
// Nichts, was die KI schreibt, löst eine Aktion aus; die übersetzte Suche wird erst nach
// Prüfung durch den Benutzer angewendet.
import { h, mount, api, relTime, fmtDateTime } from "./dom.js";
import { state, card } from "./app.js";

// ---------- Markdown als Textknoten ----------

// Überschriften, Listen, **fett**, `Code`, Code-Blöcke. Listenpunkte, die mit
// „**Gefährlich:**“ beginnen, werden hervorgehoben (Skripte erklären).
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
export function renderMd(text) {
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
      if (!list) { list = h(/^\s*\d/.test(line) ? "ol" : "ul", { class: "plain" }); out.push(list); }
      list.append(h("li", { class: /^\*\*Gefährlich/i.test(li[1]) ? "ai-danger" : null }, inlineMd(li[1])));
      continue;
    }
    list = null;
    if (line.trim()) out.push(h("p", { class: "md-p" }, inlineMd(line)));
  }
  if (code) out.push(h("pre", { class: "plain mono" }, code.join("\n")));
  return h("div", { class: "md" }, out);
}

// ---------- Stand ----------

let statusCache = null, statusAt = 0;
// aiStatus: welche KI-Funktionen an sind (30 s gemerkt, damit nicht jede Karte fragt).
export function aiStatus() {
  if (!statusCache || Date.now() - statusAt > 30000) {
    statusAt = Date.now();
    statusCache = api("ai/status").catch(() => ({}));
  }
  return statusCache;
}
export function aiStatusReset() { statusCache = null; }
const isAdmin = () => !!state.user && state.user.role === "admin";
const fmtDay = (ms) => new Date(ms).toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit", year: "numeric" });

// ---------- Kurzanalysen ----------

export function briefBox(b) {
  return h("div", { class: "ai-brief" },
    h("div", { class: "k" }, h("span", { class: "badge ai" }, "KI-Kurzanalyse"),
      h("span", { class: "muted" }, " automatisch · ", relTime(b.at), b.reused ? " · von einem ähnlichen Angriff übernommen" : "")),
    h("p", null, b.text));
}

// loadBriefs: Kurzanalysen zu Angriffen ({Kennung: Analyse}); Fehler ergeben nichts.
export async function loadBriefs(ids) {
  if (!ids.length) return {};
  try { return (await api("ai/briefs?ids=" + ids.slice(0, 100).map(encodeURIComponent).join(","))).briefs || {}; } catch { return {}; }
}

// briefsForIP: alle Kurzanalysen einer IP (Angriffsbericht); leer, wenn es keine gibt.
export function briefsForIP(ip) {
  const box = h("div");
  api("ai/briefs?ip=" + encodeURIComponent(ip)).then((d) => {
    const list = Object.values(d.briefs || {}).sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
    if (list.length) mount(box, h("h3", null, "KI-Kurzanalyse"), list.slice(0, 3).map(briefBox),
      h("p", { class: "muted aw-small" }, "Automatisch von einem Sprachmodell erzeugt; kann Fehler enthalten."));
  }).catch(() => {});
  return box;
}

// ---------- Skripte erklären ----------

// explainSlot: Knopf „Mit KI erklären“ für die Befehle eines Berichts ({ip} oder {session})
// oder eine nachgeladene Datei ({hash}); nur für Admins und wenn die Funktion an ist.
export function explainSlot(target) {
  const slot = h("div", { class: "ai-explain" });
  if (!isAdmin()) return slot;
  aiStatus().then((st) => {
    if (!st.ai_enabled || !st.explain) return;
    const out = h("div");
    const btn = h("button", { class: "btn small" }, "Mit KI erklären");
    const run = async (force) => {
      btn.disabled = true;
      mount(out, h("p", { class: "muted" }, "Das Modell erklärt Schritt für Schritt …"));
      try {
        const d = await api("ai/explain", { method: "POST", body: { ...target, force } });
        btn.hidden = true;
        mount(out, h("h4", { class: "md-h" }, "Erklärung der KI",
          h("span", { class: "muted" }, " · ", d.cached ? "gespeichert, " : "", relTime(d.explain.at))),
        renderMd(d.explain.text),
        h("p", { class: "muted aw-small" }, "Von einem Sprachmodell erzeugt; kann Fehler enthalten. Ausgeführt wurde nichts. ",
          h("button", { class: "linklike", onclick: () => run(true) }, "neu erklären lassen")));
      } catch (e) { mount(out, h("div", { class: "msg err" }, e.message)); }
      btn.disabled = false;
    };
    btn.onclick = () => run(false);
    mount(slot, btn, out);
  });
  return slot;
}

// ---------- Suche in Alltagssprache ----------

// aiSearch: Eingabe für eine Frage; die KI schlägt eine Suche vor, die der Benutzer prüft,
// ändern kann und erst dann mit apply(q, range) anwendet. ranges: [[Wert, Name], …]
export function aiSearch(apply, ranges) {
  const slot = h("div", { class: "ai-search", hidden: true });
  if (!isAdmin()) return slot;
  aiStatus().then((st) => {
    if (!st.ai_enabled || !st.search) return;
    const inp = h("input", { type: "text", maxlength: 300, placeholder: "Frage in Alltagssprache, z. B. SSH-Angriffe aus China mit Download diese Woche",
      "aria-label": "Frage an die KI", style: { flex: "1", minWidth: "260px" } });
    const btn = h("button", { class: "btn", type: "submit" }, "Übersetzen");
    const res = h("div", { class: "ai-search-res", hidden: true });
    const form = h("form", { class: "filters", onsubmit: async (e) => {
      e.preventDefault();
      const q = inp.value.trim();
      if (!q) return;
      btn.disabled = true;
      res.hidden = false;
      mount(res, h("p", { class: "muted" }, "Die KI übersetzt die Frage in die Suchsprache …"));
      try {
        const d = await api("ai/search", { method: "POST", body: { question: q } });
        const qIn = h("input", { type: "text", value: d.q, class: "mono", maxlength: 500, "aria-label": "Übersetzte Suche", style: { flex: "1", minWidth: "260px" } });
        const sel = h("select", { "aria-label": "Zeitraum" }, ranges.map(([v, l]) => h("option", { value: v, selected: v === d.range }, l)));
        mount(res,
          h("p", { class: "muted" }, "Vorschlag der KI – bitte prüfen und bei Bedarf ändern.", d.note ? " " + d.note : ""),
          h("div", { class: "filters" }, qIn, sel,
            h("button", { class: "btn primary", type: "button", onclick: () => { const v = qIn.value.trim(); if (v) { res.hidden = true; apply(v, sel.value); } } }, "Suche anwenden"),
            h("button", { class: "btn", type: "button", onclick: () => { res.hidden = true; } }, "Verwerfen")));
      } catch (err) { mount(res, h("div", { class: "msg err" }, err.message)); }
      btn.disabled = false;
    } }, h("span", { class: "badge ai" }, "KI"), inp, btn);
    slot.hidden = false;
    mount(slot, form, res);
  });
  return slot;
}

// ---------- KI-Wochenbericht (oben unter Erkenntnisse) ----------

export function weeklyAICard() {
  const body = h("div", { class: "muted" }, "Lade …");
  const el = card("KI-Wochenbericht", body);
  el.hidden = true;
  const msg = h("span", { class: "muted" });
  const btn = h("button", { class: "btn small" }, "Neu erstellen");
  const show = (s) => mount(body,
    s ? [h("p", { class: "muted aw-small" }, `${fmtDay(s.from)} bis ${fmtDay(s.to - 60000)} · erstellt ${fmtDateTime(s.at)}`), renderMd(s.text)]
      : h("p", { class: "muted" }, "Noch kein KI-Wochenbericht. Er entsteht montags ab 8 Uhr für die vergangene Woche oder hier auf Knopfdruck."),
    h("div", { class: "btnrow" }, isAdmin() ? btn : null, msg),
    h("p", { class: "muted aw-small" }, "Von einem Sprachmodell aus den Zahlen der letzten sieben Tage erzeugt; kann Fehler enthalten."));
  btn.onclick = async () => {
    btn.disabled = true;
    msg.textContent = " Das Modell fasst die Woche zusammen …";
    try { show((await api("ai/weekly", { method: "POST" })).summary); msg.textContent = ""; } catch (e) { msg.textContent = " Fehler: " + e.message; }
    btn.disabled = false;
  };
  aiStatus().then(async (st) => {
    if (!st.ai_enabled || !st.weekly) return;
    el.hidden = false;
    try { show((await api("ai/weekly")).summary); } catch (e) { mount(body, h("div", { class: "msg err" }, e.message)); }
  });
  return el;
}
