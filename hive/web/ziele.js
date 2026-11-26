// Gemeinsame Klickziele der Übersicht: Jede Kennzahl, Kachel oder Zeile führt in allen Themes
// zur selben Liste wie im Standard (app.js, viewDashboard). Themes holen die Adresse hier ab,
// statt eigene Wege zu bauen, damit man sich in jedem Look gleich zurechtfindet.
//
//   ziel("connect", "7d")  → "#/attacks?range=7d"
//   zielTitel("funde")     → "Klick zeigt die Funde"
//
// Schlüssel: connect (Verbindungen), ips (Angreifer-IPs), attacks (Angriffe), login (Login-Versuche),
// request (Web-Anfragen), success (Logins angenommen), fetch (Nachladeversuche), funde (Funde),
// active (Aktiv, 15 Min), tarpit, countries (Herkunft), services (Dienste), creds (Zugangsdaten),
// insights (Erkenntnisse), analysis (Analyse). Dazu ip(), land(), dienst(), stufe(), fund().

const enc = encodeURIComponent;

export const ZIELE = {
  connect: (r) => `#/attacks?range=${r}`,
  ips: (r) => `#/attacks?range=${r}`,
  attacks: (r) => `#/attacks?range=${r}`,
  active: () => "#/attacks",
  login: () => "#/feed?type=login",
  request: () => "#/feed?type=request",
  success: (r) => `#/attacks?range=${r}&success=1`,
  fetch: (r) => `#/attacks?range=${r}&q=nachladen:ja`,
  funde: () => "#/funde", // Funde nimmt den Zeitraum der Übersicht (state.range) selbst mit
  tarpit: () => "#/tarpit",
  countries: () => "#/analysis",
  services: () => "#/analysis",
  creds: () => "#/creds",
  insights: () => "#/insights",
  analysis: () => "#/analysis",
};

const TITEL = {
  connect: "die Angriffe", ips: "die Angriffe", attacks: "die Angriffe", active: "die gerade aktiven Angriffe",
  login: "die Login-Versuche", request: "die Web-Anfragen", success: "die Angriffe mit angenommenem Login",
  fetch: "die Angriffe mit Nachladeversuch", funde: "die Funde", tarpit: "den Tarpit", countries: "die Analyse",
  services: "die Analyse", creds: "die Zugangsdaten", insights: "die Erkenntnisse", analysis: "die Analyse",
};

/** Adresse für einen Schlüssel; r ist der Zeitraum der Übersicht (z. B. "24h"). */
export function ziel(key, r = "24h") {
  const f = ZIELE[key];
  return f ? f(r) : "#/";
}

export const zielTitel = (key) => `Klick zeigt ${TITEL[key] || "die Liste dazu"}`;

// Einzelne Dinge: immer dieselbe Seite wie im Standard
export const ip = (a) => "#/attacker/" + enc(a);
export const land = (cc, r = "24h") => `#/attacks?range=${r}&q=${enc("country:" + cc)}`;
export const dienst = (svc, r = "24h") => `#/attacks?range=${r}&service=${enc(svc)}`;
export const stufe = (n, r = "24h") => `#/attacks?range=${r}&stufe=${n}`;
export const fund = (sha) => "#/funde?f=" + enc(sha);
export const sitzung = (id) => "#/session/" + enc(id);
