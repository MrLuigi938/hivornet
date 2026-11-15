package main

import (
	"errors"
	"os"
	"strings"
	"sync/atomic"
)

// Erlaubte Hostnamen für die Web-UI (Schutz gegen DNS-Rebinding, siehe hostAllowed).
//
// Zwei Quellen, die zusammen gelten:
//   - HIVE_ALLOWED_HOSTS aus der Umgebung (kommagetrennt, auch "*"),
//   - die Liste aus den Einstellungen der Web-UI (kv "allowed_hosts", eine Zeile pro Eintrag).
// Die UI-Liste ist für Geräte ohne Konsole gedacht (Raspberry Pi), z. B. für den Namen
// hinter einem Reverse-Proxy. "*" gibt es dort nicht: Die Prüfung abschalten soll nur,
// wer an die Konfiguration des Dienstes kommt. IP-Adressen und Heimnetz-Namen sind immer
// erlaubt, ein falscher Eintrag kann also niemanden aussperren.

const (
	kvAllowedHosts  = "allowed_hosts"
	maxAllowedHosts = 32
)

type hostList struct {
	env []string
	cur atomic.Pointer[[]string] // env + UI-Liste
}

func envAllowedHosts() []string {
	var out []string
	for _, e := range strings.Split(os.Getenv("HIVE_ALLOWED_HOSTS"), ",") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// uiAllowedHosts liest die in der Web-UI gespeicherte Liste.
func (h *Hive) uiAllowedHosts() []string {
	v, _ := h.st.GetKV(kvAllowedHosts)
	var out []string
	for _, e := range strings.Split(v, "\n") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// reloadHosts setzt die wirksame Liste neu (beim Start und nach dem Speichern).
func (h *Hive) reloadHosts() {
	all := append(append([]string{}, h.hosts.env...), h.uiAllowedHosts()...)
	h.hosts.cur.Store(&all)
}

func (h *Hive) allowedHosts() []string {
	if p := h.hosts.cur.Load(); p != nil {
		return *p
	}
	return h.hosts.env
}

// normalizeHosts prüft die Eingabe aus der Web-UI: Hostnamen wie "hivornet.example.de"
// oder ".example.de" (alle Unterdomänen), ohne Schema, Port oder Pfad.
func normalizeHosts(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, e := range in {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || seen[e] {
			continue
		}
		if !validHostEntry(e) {
			return nil, errors.New("ungültiger Hostname: " + clip(e, 80) + " (nur den Namen eintragen, z. B. hivornet.example.de, ohne https:// und Port)")
		}
		seen[e] = true
		out = append(out, e)
	}
	if len(out) > maxAllowedHosts {
		return nil, errors.New("höchstens 32 Hostnamen")
	}
	return out, nil
}

func validHostEntry(e string) bool {
	name := strings.TrimPrefix(e, ".")
	if len(name) == 0 || len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// nonNil liefert für JSON eine leere Liste statt null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
