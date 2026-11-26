// Darstellung: Farbmodus (Dunkel/Hell/System) und Theme (Aussehen und Anordnung).
// Beides gilt nur für diesen Browser (localStorage), nicht für den Server.
//
// ---------- Ein Theme bauen (ohne app.js anzufassen) ----------
// 1. Eintrag in THEMES: { id, name, beschreibung, css?, modul?, farbmodus? }
//    - id         nur a–z, 0–9 und "-"; landet als data-skin am <html> (und als Klasse skin-<id>).
//    - css: true  lädt skins/<id>.css (nur solange das Theme aktiv ist). Alle Regeln darin
//                 beginnen mit html[data-skin="<id>"], damit nichts in andere Themes durchschlägt.
//    - modul: true lädt das ES-Modul skins/<id>.js. Es darf diese Einhängepunkte exportieren
//                 (alle freiwillig, jeder fehlende fällt auf den Standard zurück):
//        shell(app, teile)   baut den Rahmen in #app und gibt { main, top } zurück: main nimmt
//                            die Seiten auf, top die Kopfzeile jeder Seite (Titel, Zeitraum).
//                            teile = { user, nav: [[href, label]], brand, live, userMenu, credit, logout }
//                            sind fertige Bausteine des Standards; live behält die id "live".
//        onRoute(info)       nach jedem Seitenwechsel: { hash, navHash } (z. B. für Titel, Tasten).
//        dashboard(el, ctx, daten)  ersetzt die Darstellung der Übersicht. daten kommt aus
//                            loadDashboard() in app.js (dieselben Abfragen wie der Standard),
//                            ctx wie bei jeder Ansicht (live, every, onCleanup, current).
//        cleanup()           beim Wechsel auf ein anderes Theme: Tasten, Timer, Vollbild abräumen.
//        einstellungen()     eigene Bedienelemente (Knoten) unter Einstellungen → Darstellung,
//                            Karte „Theme“, unter der Liste; nur solange das Theme aktiv ist.
//    - farbmodus: "dark" Theme gibt es nur dunkel; der gewählte Farbmodus bleibt gemerkt.
// 2. Navigation: Links mit dem Attribut data-navlink bekommen beim Seitenwechsel die Klasse "on".
// 3. Alle anderen Seiten bleiben unverändert und werden nur über die CSS-Datei angepasst.
//
// Sicherheit: Pfade entstehen nur aus der festen Liste unten (nie aus localStorage oder der
// Adresse); die CSP der Web-UI erlaubt nur Dateien vom Hive selbst (script-src/style-src 'self'),
// also keine <style>-Blöcke und kein style="…" im HTML, Stile nur über el.style oder die CSS-Datei.
// Fehler beim Laden (Datei fehlt, Modul wirft): Standard, Meldung nur in der Konsole.
import { store } from "./dom.js";

export const THEMES = [
  { id: "standard", name: "Standard", beschreibung: "Das gewohnte Aussehen: Navigation oben, Karten und Raster wie bisher." },
  { id: "leitstand", name: "Leitstand", css: true, modul: true, farbmodus: "dark",
    beschreibung: "Lagebild für den Wandmonitor: schmale Icon-Leiste links (Tasten 1–8), Übersicht als dichtes Raster ohne Scrollen mit Live-Ticker und Angriffslinien auf der Karte, Kiosk-Modus mit Taste K. Immer dunkel." },
  { id: "kacheln", name: "Kacheln", css: true, modul: true,
    beschreibung: "Weicher Look mit schwebender Pillen-Leiste: Übersicht aus abgerundeten Kacheln, die sich umsortieren, vergrößern und ausblenden lassen (Anordnen); Klick auf eine Kachel öffnet die volle Seite. Hell und dunkel, Akzentfarbe wählbar." },
  { id: "taschenformat", name: "Taschenformat", css: true, modul: true,
    beschreibung: "Mobil zuerst: Ampel oben, Tableiste unten in Daumen-Reichweite, Übersicht als Kartenstapel mit „Seit deinem letzten Besuch“ und Weltkarte im Vollbild-Blatt, große Touch-Flächen. Am Desktop eine ruhige, zentrierte Zweispaltenansicht. Hell und dunkel." },
  { id: "terminal", name: "Terminal", css: true, modul: true, farbmodus: "dark",
    beschreibung: "Retro-Konsole wie htop oder Midnight Commander: nur Monospace, Rahmen aus Box-Zeichen, Balken und Sparklines aus Blockzeichen, Live-Feed als Log. Befehlszeile oben (/ip, /land, /stufe, /hilfe …), Fußzeile mit Tasten 1–0. Phosphor-Grün oder Bernstein, CRT-Effekt abschaltbar. Immer dunkel." },
];

export const COLOR_MODES = [
  ["dark", "Dunkel", "Dunkler Hintergrund, schont die Augen am Abend."],
  ["light", "Hell", "Heller Hintergrund."],
  ["system", "Wie das System", "Folgt der Einstellung des Geräts."],
];

const ID_RE = /^[a-z0-9-]{1,32}$/;
export const colorMode = () => (["light", "system"].includes(store("theme")) ? store("theme") : "dark");
export const themeId = () => (THEMES.some((t) => t.id === store("skin")) ? store("skin") : THEMES[0].id);
export const themeById = (id) => THEMES.find((t) => t.id === id && ID_RE.test(t.id)) || THEMES[0];

const LAYOUT_ATTRS = ["nav", "raster"]; // Attribute, die ein Theme über layout: {…} setzen darf

// Aktives Theme mit geladenem Modul; wechselt erst, wenn CSS und Modul da sind.
let current = { theme: THEMES[0], mod: null, link: null };
let loading = Promise.resolve(current), seq = 0;
const listeners = new Set();
export const activeSkin = () => current;
export const skinReady = () => loading;
// Eigene Bedienelemente des aktiven Themes für Einstellungen → Darstellung (Einhängepunkt
// einstellungen); null, wenn das Theme keine hat oder der Einhängepunkt wirft.
export function skinOptions() {
  const fn = current.mod?.einstellungen;
  if (typeof fn !== "function") return null;
  try { return fn() || null; } catch (e) { console.error("Theme-Einhängepunkt einstellungen:", e); return null; }
}
// fn(neu, alt) nach jedem Wechsel; gibt eine Abmeldefunktion zurück
export function onSkinChange(fn) { listeners.add(fn); return () => listeners.delete(fn); }

function setColor(t) {
  const mode = t.farbmodus || colorMode();
  document.documentElement.dataset.theme = mode === "light" || mode === "system" ? mode : "dark";
}

function loadCSS(t) {
  return new Promise((resolve, reject) => {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.dataset.skinCss = t.id;
    const timer = setTimeout(() => reject(new Error("Zeitüberschreitung")), 8000);
    link.onload = () => { clearTimeout(timer); resolve(link); };
    link.onerror = () => { clearTimeout(timer); link.remove(); reject(new Error("nicht gefunden")); };
    link.href = `skins/${t.id}.css`;
    document.head.appendChild(link);
  });
}

async function load(t) {
  if (t === current.theme) return current;
  const link = t.css ? await loadCSS(t) : null;
  try {
    const mod = t.modul ? await import(`./skins/${t.id}.js`) : null;
    return { theme: t, mod, link };
  } catch (e) { link?.remove(); throw e; }
}

function commit(next) {
  const prev = current;
  const root = document.documentElement, t = next.theme;
  current = next;
  setColor(t);
  root.dataset.skin = t.id;
  root.className = root.className.replace(/\bskin-\S+/g, "").trim();
  root.classList.add("skin-" + t.id);
  for (const a of LAYOUT_ATTRS) {
    if (t.layout && t.layout[a]) root.dataset[a] = t.layout[a]; else delete root.dataset[a];
  }
  if (prev.link && prev.link !== next.link) prev.link.remove();
  if (next === prev) return;
  for (const fn of listeners) { try { fn(next, prev); } catch (e) { console.error(e); } }
}

// Setzt Farbmodus sofort und das Theme, sobald es geladen ist. Ohne Argumente gelten die
// gemerkten Werte. Gibt ein Promise zurück, das nach dem Wechsel erfüllt ist.
export function applyTheme(skin = themeId()) {
  const t = themeById(skin), my = ++seq;
  setColor(t);
  loading = load(t).catch((e) => {
    console.error(`Theme „${t.id}“ ließ sich nicht laden, es gilt der Standard:`, e);
    return { theme: THEMES[0], mod: null, link: null };
  }).then((next) => {
    if (my !== seq) { if (next.link && next !== current) next.link.remove(); return current; } // inzwischen anders gewählt
    if (next.theme === THEMES[0] && current.theme === THEMES[0]) next = current;
    commit(next);
    return current;
  });
  return loading;
}

export function setColorMode(mode) { store("theme", mode); setColor(current.theme); }
export function setTheme(id) { store("skin", themeById(id).id); return applyTheme(); }
