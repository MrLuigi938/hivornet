// Karte „Verweildauer nach dem Login“ (hive/dwell.go): Messlatte für alles, was Angreifer länger
// in der Shell halten soll. Angreiferdaten kommen hier nicht vor, nur Zahlen je Dienst.
import { h, mount, api, fmtNum, fmtDur } from "./dom.js";
import { svcName } from "./charts.js";
import { state, card } from "./app.js";

const pct = (a, b) => (b ? Math.round((100 * a) / b) + " %" : "–");
const dur = (ms) => (ms > 0 ? (ms < 60000 ? (ms / 1000).toFixed(1).replace(".", ",") + " s" : fmtDur(ms)) : "–");
const cmds = (v) => (v || v === 0 ? String(Math.round(v * 10) / 10).replace(".", ",") : "–");

export function dwellCard() {
  const body = h("div", { class: "muted" }, "Wird berechnet …");
  const col = (t, title) => h("th", { class: "num", title }, t);
  const row = (s, label) => h("tr", null,
    h("td", null, label ? h("b", null, label) : svcName(s.service)),
    h("td", { class: "num" }, fmtNum(s.logins)),
    h("td", { class: "num" }, s.logins ? pct(s.no_cmd, s.logins) : "–"),
    h("td", { class: "num" }, s.logins ? dur(s.median_dwell_ms) : "–"),
    h("td", { class: "num" }, s.logins ? cmds(s.median_cmds) + " / " + cmds(s.avg_cmds) : "–"),
    h("td", { class: "num" }, s.check_sessions ? `${fmtNum(s.check_follow)} von ${fmtNum(s.check_sessions)}` : "–"),
    h("td", { class: "num" }, s.return_ips ? `${pct(s.return_back, s.return_ips)} (${fmtNum(s.return_back)} von ${fmtNum(s.return_ips)})` : "–"));
  api("dwell?range=" + state.range).then((d) => {
    const rows = d.services || [];
    if (!rows.length && !d.total.logins) { mount(body, h("div", { class: "empty" }, "Im Zeitraum keine Sitzung mit angenommenem Login.")); return; }
    mount(body, h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, h("th", null, "Dienst"), col("Logins", "Sitzungen mit angenommenem Login"),
        col("ohne Befehl", "Anteil der Logins, nach denen kein einziger Befehl kam"),
        col("Median Dauer", "Dauer vom Login bis zum Ende der Verbindung"),
        col("Befehle Median / Ø", "Befehle je Sitzung mit Login"),
        col("nach Prüfreihe weiter", "Sitzungen mit Honeypot-Prüfreihe, in denen danach noch ein Befehl oder Download kam"),
        col("Wiederkehr 7 Tage", `IPs mit erstem Login vor 7 bis ${d.return_cohort_days + 7} Tagen, die binnen 7 Tagen danach erneut verbunden haben`))),
      h("tbody", null, rows.map((s) => row(s)), row(d.total, "Alle")))),
      d.truncated ? h("p", { class: "muted aw-small" }, "Zeitraum ist sehr groß: es wurden nur die ältesten Ereignisse gewertet.") : null);
  }).catch((e) => mount(body, h("div", { class: "msg err" }, e.message)));
  return card("Verweildauer nach dem Login",
    h("p", { class: "sub" }, "Nur Sitzungen mit angenommenem Login. Die Wiederkehr gilt unabhängig vom Zeitraum für IPs, deren erster Login 7 bis 37 Tage zurückliegt. Vor jeder Änderung an Shell oder Köder ablesen, danach vergleichen."),
    body);
}
