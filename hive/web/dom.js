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

function setAttrs(el, attrs, svg) {
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "class") el.setAttribute("class", v);
    else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
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
