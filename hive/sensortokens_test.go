package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSensorTokens(t *testing.T) {
	h := testHive(t)
	h.auth = NewAuth(h.st, "gemeinsames-token", false)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if i := strings.LastIndex(path, "/"); method == "DELETE" {
			r.SetPathValue("name", path[i+1:])
		}
		h.sensorTokensAPI(w, r)
		return w
	}
	if w := call("POST", "/api/sensor-tokens", `{"name":"../böse"}`); w.Code != 400 {
		t.Fatalf("ungültiger Name angenommen: %d", w.Code)
	}
	w := call("POST", "/api/sensor-tokens", `{"name":"VPS-1"}`)
	var created struct{ Name, Token string }
	json.Unmarshal(w.Body.Bytes(), &created)
	if w.Code != 200 || created.Name != "vps-1" || len(created.Token) != 64 {
		t.Fatalf("anlegen: %d %s", w.Code, w.Body.String())
	}
	if call("POST", "/api/sensor-tokens", `{"name":"vps-1"}`).Code != 409 {
		t.Error("doppelter Name angenommen")
	}
	if v, _ := h.st.GetKV(sensorTokensKV); strings.Contains(v, created.Token) {
		t.Error("Token im Klartext gespeichert")
	}

	// Lebenszeichen: mit Sensor-Token gilt immer der gebundene Name
	hb := func(tok, claimed string) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/sensor/heartbeat", strings.NewReader(`{"sensor":"`+claimed+`","version":"x"}`))
		r.Header.Set("Authorization", "Bearer "+tok)
		h.auth.RequireSensor(h.heartbeat)(w, r)
		return w.Code
	}
	if c := hb(created.Token, "sensor-1"); c != 200 {
		t.Fatalf("Lebenszeichen: %d", c)
	}
	if _, ok := h.sensors.last["vps-1"]; !ok {
		t.Errorf("nicht unter dem gebundenen Namen: %v", h.sensors.last)
	}
	if _, ok := h.sensors.last["sensor-1"]; ok {
		t.Error("Sensor konnte sich als sensor-1 ausgeben")
	}
	if c := hb("gemeinsames-token", "sensor-1"); c != 200 {
		t.Errorf("gemeinsames Token: %d", c)
	}
	if c := hb("falsch", "x"); c != http.StatusUnauthorized {
		t.Errorf("falsches Token: %d", c)
	}

	// Liste ohne Token, Widerruf wirkt sofort
	if w := call("GET", "/api/sensor-tokens", ""); !strings.Contains(w.Body.String(), `"name":"vps-1"`) || strings.Contains(w.Body.String(), created.Token) {
		t.Errorf("Liste: %s", w.Body.String())
	}
	if w := call("DELETE", "/api/sensor-tokens/vps-1", ""); w.Code != 200 {
		t.Fatalf("widerrufen: %d", w.Code)
	}
	if c := hb(created.Token, "x"); c != http.StatusUnauthorized {
		t.Errorf("widerrufenes Token gilt noch: %d", c)
	}
	if viewerAllowed(httptest.NewRequest("GET", "/api/sensor-tokens", nil)) {
		t.Error("Leserolle darf Sensor-Tokens sehen")
	}
}
