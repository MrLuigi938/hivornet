package main

// Eigene Tokens je Sensor. Neben dem gemeinsamen HIVORNET_TOKEN (eigener Honeypot im
// selben Netz) kann der Admin weitere Sensoren anlegen, z. B. einen Honeypot auf einem
// kleinen Server im Rechenzentrum. Jedes Token
//   - wird nur einmal angezeigt und in der Datenbank nur als SHA-256 gespeichert,
//   - ist an seinen Sensor-Namen gebunden: Ereignisse, Lebenszeichen und Konfiguration
//     gelten immer für diesen Namen, egal was der Sensor selbst angibt,
//   - lässt sich einzeln widerrufen.
// Verschlüsselt wird nicht hier: Ein entfernter Sensor sollte den Hive über ein VPN
// (z. B. WireGuard) erreichen, die Sensor-API gehört nicht ins Internet.
//
//   GET    /api/sensor-tokens          Liste (Name, angelegt, zuletzt benutzt)
//   POST   /api/sensor-tokens          {"name": "vps-1"} -> {"name", "token"} (einmalig)
//   DELETE /api/sensor-tokens/{name}   widerrufen

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const sensorTokensKV = "sensor_tokens"

type sensorToken struct {
	Hash     string `json:"hash"`
	Created  int64  `json:"created"`
	LastUsed int64  `json:"last_used,omitempty"`
	Trusted  bool   `json:"trusted,omitempty"` // darf Blockliste und AbuseIPDB speisen (protect.go)
}

var sensorNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

type sensorTokenStore struct {
	mu     sync.Mutex
	loaded bool
	m      map[string]*sensorToken // Name -> Token
	dirty  time.Time               // zuletzt-benutzt nur gelegentlich schreiben
}

type ctxKey string

const boundSensorKey ctxKey = "sensor"

// boundSensor: Name, an den das Token der Anfrage gebunden ist ("" = gemeinsames Token).
func boundSensor(r *http.Request) string {
	s, _ := r.Context().Value(boundSensorKey).(string)
	return s
}

func (a *Auth) loadSensorTokens() {
	if a.tokens.loaded || a.st == nil {
		return
	}
	a.tokens.m = map[string]*sensorToken{}
	if v, ok := a.st.GetKV(sensorTokensKV); ok {
		json.Unmarshal([]byte(v), &a.tokens.m)
	}
	a.tokens.loaded = true
}

func (a *Auth) saveSensorTokens() error {
	b, _ := json.Marshal(a.tokens.m)
	return a.st.SetKV(sensorTokensKV, string(b))
}

// sensorFor prüft ein Token gegen die Sensor-Tokens; liefert den Namen oder "".
func (a *Auth) sensorFor(tok string) string {
	if tok == "" || a.st == nil {
		return ""
	}
	h := tokenHash(tok)
	a.tokens.mu.Lock()
	defer a.tokens.mu.Unlock()
	a.loadSensorTokens()
	for name, t := range a.tokens.m {
		if subtle.ConstantTimeCompare([]byte(h), []byte(t.Hash)) == 1 {
			now := time.Now()
			t.LastUsed = now.UnixMilli()
			if now.Sub(a.tokens.dirty) > 10*time.Minute {
				a.tokens.dirty = now
				a.saveSensorTokens()
			}
			return name
		}
	}
	return ""
}

func (h *Hive) sensorTokensAPI(w http.ResponseWriter, r *http.Request) {
	a := h.auth
	a.tokens.mu.Lock()
	defer a.tokens.mu.Unlock()
	a.loadSensorTokens()
	switch r.Method {
	case "POST":
		var in struct{ Name string }
		if json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&in) != nil {
			httpErr(w, 400, "ungültige Eingabe")
			return
		}
		name := strings.ToLower(strings.TrimSpace(in.Name))
		if !sensorNameRe.MatchString(name) {
			httpErr(w, 400, "Name: 1 bis 32 Zeichen, Kleinbuchstaben, Ziffern, Punkt, Binde- und Unterstrich")
			return
		}
		if _, dup := a.tokens.m[name]; dup {
			httpErr(w, 409, "Sensor gibt es schon; zum Erneuern erst widerrufen")
			return
		}
		if len(a.tokens.m) >= 20 {
			httpErr(w, 400, "höchstens 20 Sensoren")
			return
		}
		tok := randToken(32)
		a.tokens.m[name] = &sensorToken{Hash: tokenHash(tok), Created: time.Now().UnixMilli()}
		if err := a.saveSensorTokens(); err != nil {
			httpErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]string{"name": name, "token": tok})
		return
	case "DELETE":
		name := r.PathValue("name")
		if _, ok := a.tokens.m[name]; !ok {
			httpErr(w, 404, "unbekannter Sensor")
			return
		}
		delete(a.tokens.m, name)
		if err := a.saveSensorTokens(); err != nil {
			httpErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
		return
	}
	type row struct {
		Name     string `json:"name"`
		Created  int64  `json:"created"`
		LastUsed int64  `json:"last_used,omitempty"`
		Trusted  bool   `json:"trusted"`
	}
	out := []row{}
	for n, t := range a.tokens.m {
		out = append(out, row{n, t.Created, t.LastUsed, t.Trusted})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, out)
}

// withSensor bindet die Anfrage an einen Sensor-Namen (für ingest, heartbeat, config).
func withSensor(r *http.Request, name string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), boundSensorKey, name))
}

// sensorTrust: POST /api/sensor-tokens/{name}/trust {"trusted": true|false}
func (h *Hive) sensorTrust(w http.ResponseWriter, r *http.Request) {
	var in struct{ Trusted bool }
	if json.NewDecoder(io.LimitReader(r.Body, 256)).Decode(&in) != nil {
		httpErr(w, 400, "ungültige Eingabe")
		return
	}
	a := h.auth
	a.tokens.mu.Lock()
	defer a.tokens.mu.Unlock()
	a.loadSensorTokens()
	t := a.tokens.m[r.PathValue("name")]
	if t == nil {
		httpErr(w, 404, "unbekannter Sensor")
		return
	}
	t.Trusted = in.Trusted
	if err := a.saveSensorTokens(); err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	h.feed.mu.Lock()
	h.feed.key = "" // Blockliste neu berechnen
	h.feed.mu.Unlock()
	writeJSON(w, map[string]bool{"ok": true})
}
