package main

// "Wie Shodan dich sieht" (Seite System): fragt bei Shodan InternetDB (kostenlos, ohne
// Schlüssel) ab, was über die öffentliche Adresse des Honeypots bekannt ist: offene Ports,
// Hostnamen, Kennzeichen (darunter "honeypot", wenn Shodan das Gerät als solchen erkannt
// hat) und bekannte Lücken. Nur auf Knopfdruck; das Ergebnis wird 24 Stunden gespeichert.
//
//   GET /api/exposure            letztes gespeichertes Ergebnis
//   POST /api/exposure {"ip":…}  neu abfragen; ohne ip wird die öffentliche Adresse bei
//                                api.ipify.org ermittelt
//
// Datenschutz: Shodan erfährt nur die eigene öffentliche Adresse, ipify ebenso (nur, wenn
// keine Adresse angegeben ist).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	internetDBBase = "https://internetdb.shodan.io/"
	ipifyURL       = "https://api.ipify.org?format=json"
)

type Exposure struct {
	IP        string   `json:"ip"`
	Indexed   bool     `json:"indexed"` // Shodan kennt die Adresse
	Ports     []int    `json:"ports"`
	Hostnames []string `json:"hostnames"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
	CPEs      []string `json:"cpes"`
	Honeypot  bool     `json:"honeypot"` // Shodan führt das Gerät als Honeypot
	Fetched   int64    `json:"fetched"`
	Detected  bool     `json:"detected,omitempty"` // Adresse selbst ermittelt
}

func publicIP(ctx context.Context) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", ipifyURL, nil)
	resp, err := intelHTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("öffentliche Adresse nicht ermittelbar: %w", err)
	}
	defer resp.Body.Close()
	var v struct{ IP string }
	if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&v) != nil || net.ParseIP(v.IP) == nil {
		return "", fmt.Errorf("öffentliche Adresse nicht ermittelbar")
	}
	return v.IP, nil
}

func fetchExposure(ctx context.Context, ip string) (Exposure, error) {
	e := Exposure{IP: ip, Ports: []int{}, Hostnames: []string{}, Tags: []string{}, Vulns: []string{}, CPEs: []string{}, Fetched: time.Now().UnixMilli()}
	req, _ := http.NewRequestWithContext(ctx, "GET", internetDBBase+ip, nil)
	resp, err := intelHTTP.Do(req)
	if err != nil {
		return e, fmt.Errorf("Shodan nicht erreichbar: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return e, nil // Shodan kennt die Adresse (noch) nicht
	}
	if resp.StatusCode != 200 {
		return e, fmt.Errorf("Shodan antwortet %s", resp.Status)
	}
	var v struct {
		Ports     []int    `json:"ports"`
		Hostnames []string `json:"hostnames"`
		Tags      []string `json:"tags"`
		Vulns     []string `json:"vulns"`
		CPEs      []string `json:"cpes"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v); err != nil {
		return e, fmt.Errorf("Antwort von Shodan unlesbar")
	}
	e.Indexed = true
	clipList := func(in []string, n int) []string {
		out := []string{}
		for _, s := range in {
			if len(out) < n {
				out = append(out, clip(s, 120))
			}
		}
		return out
	}
	e.Ports = v.Ports[:min(len(v.Ports), 200)]
	e.Hostnames, e.Tags, e.Vulns, e.CPEs = clipList(v.Hostnames, 20), clipList(v.Tags, 20), clipList(v.Vulns, 50), clipList(v.CPEs, 30)
	for _, t := range e.Tags {
		if strings.EqualFold(t, "honeypot") {
			e.Honeypot = true
		}
	}
	return e, nil
}

func (h *Hive) exposure(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		data, _, ok := h.st.lookupGet("self", "internetdb", 0)
		if !ok {
			writeJSON(w, map[string]any{})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, data)
		return
	}
	var in struct{ IP string }
	json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&in)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ip, detected := strings.TrimSpace(in.IP), false
	if cur := h.ownIPState().Current; ip == "" && len(cur) > 0 && h.Extras().OwnIP.Auto {
		ip, detected = cur[0], true // automatisch ermittelt (ownip.go)
	}
	if ip == "" {
		var err error
		if ip, err = publicIP(ctx); err != nil {
			httpErr(w, 502, err.Error())
			return
		}
		detected = true
	}
	p := net.ParseIP(ip)
	if p == nil || p.IsPrivate() || p.IsLoopback() || p.IsUnspecified() || p.IsLinkLocalUnicast() {
		httpErr(w, 400, "bitte die öffentliche IP-Adresse des Anschlusses angeben")
		return
	}
	e, err := fetchExposure(ctx, p.String())
	if err != nil {
		httpErr(w, 502, err.Error())
		return
	}
	e.Detected = detected
	b, _ := json.Marshal(e)
	h.st.lookupPut("self", "internetdb", string(b))
	writeJSON(w, e)
}
