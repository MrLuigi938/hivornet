package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExposure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ipify":
			w.Write([]byte(`{"ip":"198.51.100.20"}`))
		case "/198.51.100.20":
			w.Write([]byte(`{"ip":"198.51.100.20","ports":[22,23,80],"hostnames":["x.example"],"tags":["honeypot","self-signed"],"vulns":[],"cpes":[]}`))
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"detail":"No information available"}`))
		}
	}))
	defer srv.Close()
	oldDB, oldIP := internetDBBase, ipifyURL
	internetDBBase, ipifyURL = srv.URL+"/", srv.URL+"/ipify"
	t.Cleanup(func() { internetDBBase, ipifyURL = oldDB, oldIP })

	h := testHive(t)
	post := func(body string) (int, Exposure) {
		w := httptest.NewRecorder()
		h.exposure(w, httptest.NewRequest("POST", "/api/exposure", strings.NewReader(body)))
		var e Exposure
		json.Unmarshal(w.Body.Bytes(), &e)
		return w.Code, e
	}
	code, e := post(`{}`)
	if code != 200 || !e.Detected || !e.Indexed || !e.Honeypot || len(e.Ports) != 3 {
		t.Fatalf("selbst ermittelt: %d %+v", code, e)
	}
	if code, e = post(`{"ip":"203.0.113.1"}`); code != 200 || e.Indexed || e.Honeypot {
		t.Errorf("unbekannte Adresse: %d %+v", code, e)
	}
	if code, _ = post(`{"ip":"192.168.1.1"}`); code != 400 {
		t.Errorf("private Adresse: %d", code)
	}
	w := httptest.NewRecorder()
	h.exposure(w, httptest.NewRequest("GET", "/api/exposure", nil))
	if !strings.Contains(w.Body.String(), `"203.0.113.1"`) {
		t.Errorf("gespeichert: %s", w.Body.String())
	}
}
