// Kleine DOM-Helfer. Texte werden IMMER als Textknoten eingefügt, nie als HTML:
// alles, was Angreifer schicken (Befehle, User-Agents, Pfade), bleibt so harmlos.

const SVGNS = "http://www.w3.org/2000/svg";

// Steuerzeichen und Richtungszeichen (z. B. U+202E) aus Angreifertexten sichtbar
// ersetzen, damit sie die Anzeige nicht verdrehen oder Inhalte verstecken.
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F؜​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;
export const safeText = (s) => String(s).replace(CONTROL, (c) => `⟨U+${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}⟩`);

// Flagge als Emoji aus dem Ländercode. Angezeigt wird sie mit der eingebetteten
// Schrift "Twemoji Country Flags" (flags.woff2), weil Windows Flaggen-Emojis sonst
// nur als zwei Buchstaben darstellt.
export function flag(cc) {
  if (!/^[A-Z]{2}$/.test(cc || "")) return null;
  const emoji = String.fromCodePoint(...[...cc].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
  const el = document.createElement("span");
  el.className = "flag";
  el.setAttribute("aria-hidden", "true");
  el.textContent = emoji;
  return el;
}

function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(safeText(k)));
  }
}

// Adress-Attribute nur mit harmlosen Schemata (zweite Sicherung, Hinweis aus dem dritten
// Audit): relativ, http(s), mailto oder blob. javascript:, data: und alles andere wird
// nicht gesetzt. Browser übergehen Leer- und Steuerzeichen im Schema ("java\tscript:"),
// darum werden sie vor der Prüfung entfernt.
const URL_ATTRS = new Set(["href", "src", "action", "formaction", "xlink:href", "poster", "srcset"]);
const SAFE_SCHEME = new Set(["http", "https", "mailto", "blob"]);
export function safeURL(v) {
  const m = /^([a-z][a-z0-9+.-]*):/i.exec(String(v).replace(/[\u0000- \u007f-\u009f]/g, ""));
  return !m || SAFE_SCHEME.has(m[1].toLowerCase());
}

function setAttrs(el, attrs, svg) {
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (URL_ATTRS.has(k.toLowerCase()) && !safeURL(v)) continue;
    if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "class") el.setAttribute("class", v);
    else if (k === "style" && typeof v === "object") {
      for (const [sk, sv] of Object.entries(v)) sk.startsWith("--") ? el.style.setProperty(sk, sv) : (el.style[sk] = sv);
    }
    else if (k === "dataset") Object.assign(el.dataset, v);
    else if (!svg && (k === "value" || k === "checked" || k === "disabled" || k === "selected")) el[k] = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
}

export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  setAttrs(el, attrs, false);
  append(el, kids);
  return el;
}

export function s(tag, attrs, ...kids) {
  const el = document.createElementNS(SVGNS, tag);
  setAttrs(el, attrs, true);
  append(el, kids);
  return el;
}

export function mount(el, ...kids) {
  el.replaceChildren();
  append(el, kids);
  return el;
}

// ---------- API ----------

export class AuthError extends Error {}

export async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", credentials: "same-origin", headers: {} };
  if (init.method !== "GET") init.headers["X-Requested-With"] = "hivornet";
  if (opts.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  const r = await fetch("api/" + path, init);
  let data = null;
  try { data = await r.json(); } catch { /* leer */ }
  if (r.status === 401 && !opts.noAuthRedirect) throw new AuthError("nicht angemeldet");
  if (!r.ok) throw new Error((data && data.error) || r.statusText);
  return data;
}

// ---------- Formatierung ----------

const nf = new Intl.NumberFormat("de-DE");
export const fmtNum = (n) => nf.format(Number(n) || 0);

export function fmtBytes(b) {
  if (b === undefined || b === null || b < 0) return "–";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i ? b.toFixed(1).replace(".", ",") : b) + " " + u[i];
}

export function fmtDur(ms) {
  ms = Number(ms) || 0;
  if (ms < 1000) return ms + " ms";
  let sec = Math.round(ms / 1000);
  const d = Math.floor(sec / 86400); sec -= d * 86400;
  const hh = Math.floor(sec / 3600); sec -= hh * 3600;
  const mm = Math.floor(sec / 60); sec -= mm * 60;
  if (d) return `${d} T ${hh} Std`;
  if (hh) return `${hh} Std ${mm} Min`;
  if (mm) return `${mm} Min ${sec} s`;
  return `${sec} s`;
}

const dtf = new Intl.DateTimeFormat("de-DE", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
const tf = new Intl.DateTimeFormat("de-DE", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
export function toMs(t) { return typeof t === "number" ? t : Date.parse(t); }
export function fmtTime(t) {
  const ms = toMs(t);
  if (!ms) return "–";
  const d = new Date(ms);
  return Date.now() - ms < 86400000 && d.getDate() === new Date().getDate() ? tf.format(d) : dtf.format(d);
}
export function fmtDateTime(t) { const ms = toMs(t); return ms ? dtf.format(new Date(ms)) : "–"; }

// Uhrzeit "HH:MM" (für Achsen und Zeitspannen); fmtClockDay setzt bei einem anderen Tag als heute "TT.MM." davor.
const hm = new Intl.DateTimeFormat("de-DE", { hour: "2-digit", minute: "2-digit" });
const dm = new Intl.DateTimeFormat("de-DE", { day: "2-digit", month: "2-digit" });
const sameDay = (a, b) => new Date(a).toDateString() === new Date(b).toDateString();
export function fmtClock(t) { const ms = toMs(t); return ms ? hm.format(new Date(ms)) : "–"; }
export function fmtClockDay(t, ref = Date.now()) {
  const ms = toMs(t);
  if (!ms) return "–";
  return (sameDay(ms, ref) ? "" : dm.format(new Date(ms)).replace(/\.?$/, ".") + " ") + hm.format(new Date(ms));
}
// Zeitspanne: "17:43–18:02"; ist der Beginn nicht von heute, steht das Datum davor, bei Tageswechsel auch beim Ende.
export function fmtSpan(first, last) {
  const a = toMs(first), b = toMs(last);
  if (!a || !b) return "–";
  return fmtClockDay(a) + "–" + (sameDay(a, b) ? fmtClock(b) : fmtClockDay(b, a));
}

// Plural: plural(1, "Sitzung", "Sitzungen") -> "1 Sitzung", plural(2, ...) -> "2 Sitzungen"
export function plural(n, ein, mehr) { return `${fmtNum(n)} ${Number(n) === 1 ? ein : mehr}`; }

// Anzeige einer Zugangsdaten-Kombination "Benutzer / Passwort": leere Teile heißen "(leer)", nicht nur " / "
export function credText(key) {
  const k = String(key ?? ""), i = k.indexOf(" / ");
  if (i < 0) return k.trim() === "/" ? "(leer) / (leer)" : k;
  return `${k.slice(0, i) || "(leer)"} / ${k.slice(i + 3) || "(leer)"}`;
}

// Wann gilt ein Angreifer als "aktiv"? Eine Definition für Kopfzeile, Seite Angriffe, Dashboard und Profil:
// Aktivität in den letzten 15 Minuten (gleich dem Abstand, der Ereignisse zu einem Angriff bündelt, hive/attacks.go).
// "Läuft gerade" ist enger (unter einer Minute) und heißt deshalb anders.
export const ACTIVE_MS = 15 * 60e3, LIVE_MS = 60e3;
export const ACTIVE_TITLE = "aktiv = Aktivität in den letzten 15 Minuten";
export function activeBadge(last, now = Date.now()) {
  const age = now - toMs(last);
  if (age < LIVE_MS) return h("span", { class: "badge active", title: "läuft gerade = letztes Ereignis vor weniger als einer Minute" }, "● läuft gerade");
  if (age < ACTIVE_MS) return h("span", { class: "badge active", title: ACTIVE_TITLE }, "● aktiv");
  return null;
}

export function relTime(t) {
  const ms = toMs(t);
  if (!ms || ms < 0 || new Date(ms).getFullYear() < 2000) return "nie";
  const d = (Date.now() - ms) / 1000;
  if (d < 5) return "gerade eben";
  if (d < 60) return `vor ${Math.round(d)} s`;
  if (d < 3600) return `vor ${Math.round(d / 60)} Min`;
  if (d < 86400) return `vor ${Math.round(d / 3600)} Std`;
  return `vor ${Math.round(d / 86400)} T`;
}

// ---------- Tooltip ----------

const tip = () => document.getElementById("tip");

export function showTip(ev, title, rows) {
  const t = tip();
  mount(t, h("div", { class: "t" }, title),
    (rows || []).map(([k, v, color]) => h("div", { class: "row" },
      h("span", null, color ? h("i", { class: "swatch", style: { background: color } }) : null, k),
      h("span", { class: "num" }, v))));
  t.hidden = false;
  moveTip(ev);
}

export function moveTip(ev) {
  const t = tip();
  const pad = 14;
  let x = ev.clientX + pad, y = ev.clientY + pad;
  const r = t.getBoundingClientRect();
  if (x + r.width > innerWidth - 8) x = ev.clientX - r.width - pad;
  if (y + r.height > innerHeight - 8) y = ev.clientY - r.height - pad;
  t.style.left = Math.max(4, x) + "px";
  t.style.top = Math.max(4, y) + "px";
}

export function hideTip() { tip().hidden = true; }

export function hoverTip(el, fn) {
  el.addEventListener("mouseenter", (e) => { const [t, r] = fn(); showTip(e, t, r); });
  el.addEventListener("mousemove", moveTip);
  el.addEventListener("mouseleave", hideTip);
  return el;
}

// ---------- Speicher pro Browser ----------

export function store(key, val) {
  try {
    if (val === undefined) return localStorage.getItem("hv." + key);
    localStorage.setItem("hv." + key, val);
  } catch { /* privates Fenster o. ä. */ }
  return null;
}

// ---------- Reiter am Fuß einer Karte (statt gestapelter Aufklapplisten) ----------
// panels([{ label, count, tone, body }], { open, key }): Eine Leiste mit Reitern; jeder zeigt
// Titel und Zähler. Ein Klick öffnet den Inhalt darunter, ein zweiter schließt ihn wieder.
// body ist ein Knoten oder eine Funktion, die ihn beim ersten Öffnen baut (lädt erst dann).
// tone "warn"/"err" färbt den Zähler. key merkt sich im Browser, welcher Reiter offen war.
let panelSeq = 0;
export function panels(items, { open = null, key = null } = {}) {
  items = items.filter(Boolean);
  const id = "pn" + ++panelSeq;
  const built = new Map();
  const body = h("div", { class: "panel-body", role: "tabpanel", hidden: true });
  let cur = -1;
  const btns = items.map((it, i) => h("button", {
    type: "button", class: "panel-tab", role: "tab", id: `${id}-${i}`, "aria-selected": "false", "aria-controls": id,
    onclick: () => show(cur === i ? -1 : i),
  }, h("span", null, it.label),
  it.count !== undefined && it.count !== null ? h("span", { class: "count" + (it.tone ? " " + it.tone : "") }, typeof it.count === "number" ? fmtNum(it.count) : it.count) : null,
  h("i", { class: "chev", "aria-hidden": "true" })));
  body.id = id;
  function show(i) {
    cur = i;
    btns.forEach((b, j) => { b.setAttribute("aria-selected", String(j === i)); b.classList.toggle("on", j === i); });
    if (key) store("panel." + key, i < 0 ? "" : items[i].label);
    if (i < 0) { body.hidden = true; mount(body); return; }
    if (!built.has(i)) built.set(i, typeof items[i].body === "function" ? items[i].body() : items[i].body);
    mount(body, built.get(i));
    body.setAttribute("aria-labelledby", btns[i].id);
    body.hidden = false;
  }
  const remembered = key ? store("panel." + key) : null;
  const start = remembered !== null && remembered !== undefined ? items.findIndex((it) => it.label === remembered) : items.findIndex((it) => it.label === open);
  if (start >= 0) show(start);
  return h("div", { class: "panels" }, h("div", { class: "panel-tabs", role: "tablist" }, btns), body);
}
