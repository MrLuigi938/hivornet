// Hardware-Monitor im Reiter System (hive/hwmon.go, GET /api/hardware):
// Ringanzeigen für CPU, Arbeitsspeicher, Temperatur und Speicherplatz, Verlauf der letzten
// Stunde und Speicher je Dienst. Alles nur als Text und SVG (dom.js), keine HTML-Senken.
import { h, s, fmtBytes, fmtDur, fmtTime, showTip, moveTip, hideTip } from "./dom.js";

// Farbe nach Schwellen: grün, gelb ab warn, rot ab crit
const level = (v, warn, crit) => (v >= crit ? "var(--critical)" : v >= warn ? "var(--warning)" : "var(--good)");
const pct = (a, b) => (b > 0 ? (100 * a) / b : 0);
const fmtPct = (v) => `${Math.round(v)} %`;

// Ringanzeige: Wert 0..100 als Bogen (270°), großer Wert in der Mitte, Unterzeile darunter
function gauge({ label, value, text, sub, color, hint }) {
  const r = 42, c = 2 * Math.PI * r, arc = c * 0.75;
  const v = Math.max(0, Math.min(100, value || 0));
  return h("div", { class: "hw-gauge", title: hint || "" },
    s("svg", { viewBox: "0 0 100 100", class: "hw-ring", "aria-hidden": "true" },
      s("circle", { cx: 50, cy: 50, r, class: "hw-track", "stroke-dasharray": `${arc} ${c}`, transform: "rotate(135 50 50)" }),
      s("circle", { cx: 50, cy: 50, r, class: "hw-val", style: { stroke: color }, "stroke-dasharray": `${(arc * v) / 100} ${c}`, transform: "rotate(135 50 50)" })),
    h("div", { class: "hw-center" }, h("div", { class: "hw-big num" }, text)),
    h("div", { class: "hw-label" }, label),
    h("div", { class: "hw-sub" }, sub));
}

// Verlauf der letzten Stunde: CPU und RAM in Prozent, Temperatur auf eigener Skala (gestrichelt)
function historyChart(hist, hasTemp) {
  const W = 600, H = 150, L = 34, R = hasTemp ? 34 : 8, T = 8, B = 20;
  const pw = W - L - R, ph = H - T - B;
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, class: "hw-chart", preserveAspectRatio: "none", role: "img", "aria-label": "Verlauf der letzten Stunde" });
  if (hist.length < 2) {
    svg.append(s("text", { x: W / 2, y: H / 2, class: "hw-axis", "text-anchor": "middle" }, "Verlauf erscheint nach den ersten Messungen"));
    return svg;
  }
  const t0 = hist[0].t, t1 = hist[hist.length - 1].t, span = Math.max(t1 - t0, 1);
  const x = (t) => L + ((t - t0) / span) * pw;
  const y = (v) => T + ph - (Math.max(0, Math.min(100, v)) / 100) * ph;
  const tMax = Math.max(85, ...hist.map((p) => p.temp || 0));
  const yt = (v) => T + ph - (Math.max(0, Math.min(tMax, v)) / tMax) * ph;
  for (const g of [0, 25, 50, 75, 100]) {
    svg.append(s("line", { x1: L, x2: W - R, y1: y(g), y2: y(g), class: "hw-grid" }),
      s("text", { x: L - 6, y: y(g) + 3, class: "hw-axis", "text-anchor": "end" }, g + "%"));
  }
  if (hasTemp) {
    for (const g of [0, Math.round(tMax / 2), Math.round(tMax)]) svg.append(s("text", { x: W - R + 6, y: yt(g) + 3, class: "hw-axis" }, g + "°"));
  }
  for (let k = 0; k <= 4; k++) {
    const t = t0 + (span * k) / 4;
    svg.append(s("text", { x: x(t), y: H - 5, class: "hw-axis", "text-anchor": k === 0 ? "start" : k === 4 ? "end" : "middle" }, fmtTime(t).slice(0, 5)));
  }
  const line = (f, cls, yy = y) => hist.map((p, i) => `${i ? "L" : "M"}${x(p.t).toFixed(1)} ${yy(f(p)).toFixed(1)}`).join("");
  const area = (f, yy = y) => `${line(f, "", yy)}L${x(t1).toFixed(1)} ${(T + ph).toFixed(1)}L${x(t0).toFixed(1)} ${(T + ph).toFixed(1)}Z`;
  svg.append(
    s("path", { d: area((p) => p.mem), class: "hw-area mem" }), s("path", { d: line((p) => p.mem), class: "hw-line mem" }),
    s("path", { d: area((p) => p.cpu), class: "hw-area cpu" }), s("path", { d: line((p) => p.cpu), class: "hw-line cpu" }));
  if (hasTemp) svg.append(s("path", { d: line((p) => p.temp || 0, "", yt), class: "hw-line temp" }));
  // Hover: nächster Messpunkt mit Werten
  const cursor = s("line", { y1: T, y2: T + ph, class: "hw-cursor", visibility: "hidden" });
  const hit = s("rect", { x: L, y: T, width: pw, height: ph, fill: "transparent" });
  svg.append(cursor, hit);
  hit.addEventListener("mousemove", (ev) => {
    const r = svg.getBoundingClientRect();
    const t = t0 + ((((ev.clientX - r.left) / r.width) * W - L) / pw) * span;
    let best = hist[0];
    for (const p of hist) if (Math.abs(p.t - t) < Math.abs(best.t - t)) best = p;
    cursor.setAttribute("x1", x(best.t)); cursor.setAttribute("x2", x(best.t)); cursor.setAttribute("visibility", "visible");
    const rows = [["CPU", fmtPct(best.cpu), "var(--s1)"], ["Arbeitsspeicher", fmtPct(best.mem), "var(--s7)"]];
    if (hasTemp) rows.push(["Temperatur", `${best.temp.toFixed(1)} °C`, "var(--s2)"]);
    showTip(ev, fmtTime(best.t), rows);
    moveTip(ev);
  });
  hit.addEventListener("mouseleave", () => { cursor.setAttribute("visibility", "hidden"); hideTip(); });
  return svg;
}

// Speicher je Dienst mit Grenze (Pi: systemd MemoryMax, Docker: Grenze des Containers)
function serviceBars(list, total) {
  return h("div", { class: "hw-svcs" }, list.map((x) => {
    const ref = x.limit > 0 ? x.limit : total;
    const p = pct(x.bytes, ref);
    return h("div", { class: "hw-svc" },
      h("div", { class: "hw-svc-top" }, h("span", null, x.label),
        h("span", { class: "num muted" }, fmtBytes(x.bytes) + (x.limit > 0 ? ` von ${fmtBytes(x.limit)}` : ""))),
      h("div", { class: "hw-bar", title: x.limit > 0 ? `${fmtPct(p)} der Grenze für diesen Dienst` : `${fmtPct(p)} des gesamten Arbeitsspeichers` },
        h("i", { style: { width: `${Math.min(100, p)}%`, background: x.limit > 0 ? level(p, 70, 90) : "var(--s7)" } })));
  }));
}

export function hardwareCard(d) {
  if (!d || !d.available) {
    return h("section", { class: "card hw" }, h("div", { class: "head" }, h("h2", null, "Hardware")),
      h("p", { class: "muted" }, "Auf diesem System nicht verfügbar (nur unter Linux, z. B. Raspberry Pi oder Docker)."));
  }
  const memP = pct(d.mem_used, d.mem_total);
  const hasTemp = d.temp > 0;
  const diskUsed = d.disk_total > 0 ? d.disk_total - d.disk_free : 0;
  const diskP = pct(diskUsed, d.disk_total);
  const gauges = [
    gauge({ label: "CPU", value: d.cpu, text: fmtPct(d.cpu), color: level(d.cpu, 60, 85),
      sub: `${d.cores} Kern${d.cores === 1 ? "" : "e"} · Last ${d.load.map((v) => v.toFixed(2)).join(" / ")}`,
      hint: "Auslastung über alle Kerne der letzten 15 Sekunden; Last = wartende Prozesse im Mittel über 1, 5 und 15 Minuten" }),
    gauge({ label: "Arbeitsspeicher", value: memP, text: fmtPct(memP), color: level(memP, 75, 90),
      sub: `${fmtBytes(d.mem_used)} von ${fmtBytes(d.mem_total)}` + (d.swap_used > 0 ? ` · Swap ${fmtBytes(d.swap_used)}` : ""),
      hint: `Belegt ohne Puffer und Cache; dazu ${fmtBytes(d.mem_cache)} Cache, den das System bei Bedarf freigibt` }),
    hasTemp ? gauge({ label: "Temperatur", value: (d.temp / 85) * 100, text: `${Math.round(d.temp)} °C`, color: level(d.temp, 65, 78),
      sub: `höchstens ${Math.round(d.temp_max || d.temp)} °C in der letzten Stunde`,
      hint: "Ab etwa 80 °C drosselt ein Raspberry Pi den Takt" }) : null,
    d.disk_total > 0 ? gauge({ label: "Speicherplatz", value: diskP, text: fmtPct(diskP), color: level(diskP, 80, 92),
      sub: `${fmtBytes(d.disk_free)} frei von ${fmtBytes(d.disk_total)}`, hint: "Dateisystem der Datenbank" }) : null,
  ].filter(Boolean);
  const thr = d.throttled && d.throttled !== "ok"
    ? h("span", { class: "badge " + (/^seit/.test(d.throttled) ? "warn" : "err"), title: "Meldung der Pi-Firmware. Häufigste Ursache: zu schwaches Netzteil oder fehlende Kühlung." }, d.throttled)
    : d.throttled === "ok" ? h("span", { class: "badge ok", title: "Keine Unterspannung, keine Drosselung seit dem Start" }, "Stromversorgung ok") : null;
  return h("section", { class: "card hw" },
    h("div", { class: "head" }, h("h2", null, "Hardware"),
      d.model ? h("span", { class: "hint" }, d.model) : null, thr, h("div", { class: "grow" }),
      h("span", { class: "hint" }, `System läuft seit ${fmtDur(d.uptime_s * 1000)} · alle ${Math.round(d.interval_ms / 1000)} s gemessen`)),
    h("div", { class: "hw-gauges" + (gauges.length === 3 ? " n3" : "") }, gauges),
    h("div", { class: "hw-lower" },
      h("div", { class: "hw-hist" },
        h("div", { class: "hw-legend" },
          h("span", null, h("i", { style: { background: "var(--s1)" } }), "CPU"),
          h("span", null, h("i", { style: { background: "var(--s7)" } }), "Arbeitsspeicher"),
          hasTemp ? h("span", null, h("i", { class: "dash", style: { background: "var(--s2)" } }), "Temperatur (rechte Skala)") : null,
          h("span", { class: "muted" }, "letzte Stunde")),
        historyChart(d.history || [], hasTemp)),
      (d.services || []).length ? h("div", { class: "hw-side" },
        h("div", { class: "hw-side-t" }, "Arbeitsspeicher je Dienst"),
        serviceBars(d.services, d.mem_total),
        h("p", { class: "muted hw-note" }, "Hive selbst: ", fmtBytes(d.hive_rss), " im Speicher")) : null));
}
