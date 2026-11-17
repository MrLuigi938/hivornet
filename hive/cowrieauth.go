package main

// Anmelderegel von Cowrie (SSH und Telnet) in der Web-UI:
//   "random": Anmeldung erst nach MIN bis MAX verschiedenen Versuchen je IP (Cowrie AuthRandom)
//   "all":    jede Kombination sofort (Cowrie UserDB mit der mitgelieferten Liste; auffällig)
//
// Raspberry Pi: Der Hive darf /etc/hivornet/cowrie.cfg nicht selbst ändern. Er legt eine
// Zeile in HIVE_COWRIE_REQUEST ab; hivornet-cowrie-config (root, per .path gestartet) prüft
// sie, trägt die Regel ein und startet Cowrie neu. Den Stand liest der Hive aus der Datei.
// Docker: Die Regel kommt aus .env (COWRIE_AUTH_CLASS, COWRIE_AUTH_PARAMS); ändern lässt sie
// sich dort, die UI zeigt sie nur an.

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type cowrieAuth struct {
	Mode string `json:"mode"` // random | all
	Min  int    `json:"min,omitempty"`
	Max  int    `json:"max,omitempty"`
}

func (c cowrieAuth) String() string {
	if c.Mode == "all" {
		return "jede Kombination sofort"
	}
	return fmt.Sprintf("nach %d bis %d Versuchen je IP", c.Min, c.Max)
}

// parseCowrieAuth liest auth_class und auth_class_parameters aus cowrie.cfg.
func parseCowrieAuth(content string) cowrieAuth {
	class, params := "", ""
	for _, line := range strings.Split(content, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "auth_class":
			class = strings.TrimSpace(v)
		case "auth_class_parameters":
			params = strings.TrimSpace(v)
		}
	}
	return authFrom(class, params)
}

func authFrom(class, params string) cowrieAuth {
	if class != "AuthRandom" {
		return cowrieAuth{Mode: "all"}
	}
	c := cowrieAuth{Mode: "random", Min: 2, Max: 5} // Standard von Cowrie
	p := strings.Split(params, ",")
	if len(p) >= 2 {
		if a, err := strconv.Atoi(strings.TrimSpace(p[0])); err == nil {
			c.Min = a
		}
		if b, err := strconv.Atoi(strings.TrimSpace(p[1])); err == nil {
			c.Max = b
		}
	}
	return c
}

func (c *cowrieAuth) valid() error {
	switch c.Mode {
	case "all":
		c.Min, c.Max = 0, 0
		return nil
	case "random":
		if c.Min < 1 || c.Max > 20 || c.Min > c.Max {
			return fmt.Errorf("Versuche: von 1 bis 20, Minimum nicht größer als Maximum")
		}
		return nil
	}
	return fmt.Errorf("unbekannte Regel")
}

// Wege auf dem Pi (Standard, falls die systemd-Unit sie noch nicht setzt)
func cowrieRequestPath() string {
	if p := os.Getenv("HIVE_COWRIE_REQUEST"); p != "" {
		return p
	}
	if logsEnabled() {
		return "/var/lib/hivornet/cowrie-request"
	}
	return ""
}

func cowrieConfigStatusPath() string {
	if p := os.Getenv("HIVE_COWRIE_CONFIG_STATUS"); p != "" {
		return p
	}
	return "/var/lib/hivornet-status/cowrie-config"
}

func (h *Hive) cowrieAuthGet(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"platform": "none"}
	switch {
	case cowrieRequestPath() != "":
		out["platform"] = "pi"
		if b, err := os.ReadFile(cowrieCfgPath); err == nil {
			cur := parseCowrieAuth(string(b))
			out["current"], out["current_text"] = cur, cur.String()
		}
		if st := readStatusFile(cowrieConfigStatusPath()); st != nil {
			out["status"] = st
		}
		_, err := os.Stat(cowrieRequestPath())
		out["pending"] = err == nil
		out["can_apply"] = true
	case h.cowrie != nil:
		out["platform"] = "docker"
		cur := authFrom(os.Getenv("HIVE_COWRIE_AUTH_CLASS"), os.Getenv("HIVE_COWRIE_AUTH_PARAMS"))
		if os.Getenv("HIVE_COWRIE_AUTH_CLASS") == "" {
			cur = authFrom("AuthRandom", "2, 5, 10") // Vorgabe in docker-compose.yml
		}
		out["current"], out["current_text"] = cur, cur.String()
	}
	writeJSON(w, out)
}

func (h *Hive) cowrieAuthPut(w http.ResponseWriter, r *http.Request) {
	var c cowrieAuth
	if readJSON(w, r, &c) != nil {
		httpErr(w, 400, "ungültige Anfrage")
		return
	}
	if err := c.valid(); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	req := cowrieRequestPath()
	if req == "" {
		httpErr(w, 400, "Im Docker-Betrieb steht die Regel in .env (COWRIE_AUTH_CLASS, COWRIE_AUTH_PARAMS); danach docker compose up -d.")
		return
	}
	line := "userdb"
	if c.Mode == "random" {
		line = fmt.Sprintf("random %d %d", c.Min, c.Max)
	}
	tmp := req + ".neu"
	if err := os.WriteFile(tmp, []byte(line+"\n"), 0o644); err != nil {
		httpErr(w, 500, "Anfrage nicht ablegbar: "+err.Error())
		return
	}
	if err := os.Rename(tmp, req); err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	h.st.SetKV("cowrie_auth_choice", line) // bewusst "jede Kombination": dann keine Warnung
	writeJSON(w, map[string]any{"ok": true, "requested": c, "text": c.String(), "at": time.Now()})
}

func (h *Hive) cowrieAllChosen() bool {
	v, _ := h.st.GetKV("cowrie_auth_choice")
	return v == "userdb"
}
