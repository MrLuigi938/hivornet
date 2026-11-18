package main

import (
	"net/http"
	"regexp"
)

// Benutzerverwaltung: Neben dem Admin-Konto aus der Ersteinrichtung kann ein Admin
// weitere Konten anlegen. Rolle "admin" darf alles, "viewer" nur ansehen (siehe
// viewerAllowed in auth.go). Alle Aufrufe hier sind nur für Admins (Require lässt
// Viewer an /api/users nicht heran).

var userNameRe = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,31}$`)

func (h *Hive) usersList(w http.ResponseWriter, r *http.Request) {
	h.sendRows(w, r, `SELECT username, role FROM users ORDER BY role, username`)
}

func (h *Hive) usersCreate(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password, Role string }
	if readJSON(w, r, &req) != nil {
		httpErr(w, 400, "ungültige Anfrage")
		return
	}
	if !userNameRe.MatchString(req.Username) {
		httpErr(w, 400, "Benutzername: 2 bis 32 Zeichen, Kleinbuchstaben, Ziffern, Punkt, Bindestrich, Unterstrich; am Anfang ein Buchstabe")
		return
	}
	if req.Role != "admin" && req.Role != "viewer" {
		httpErr(w, 400, "Rolle muss admin oder viewer sein")
		return
	}
	var n int
	h.st.db.QueryRow(`SELECT COUNT(*) FROM users WHERE username = ?`, req.Username).Scan(&n)
	if n > 0 {
		httpErr(w, 409, "Diesen Benutzer gibt es schon")
		return
	}
	if err := validPassword(req.Password); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	if err := h.auth.CreateUser(req.Username, req.Password, req.Role); err != nil { // Rolle im selben INSERT
		httpErr(w, 500, "Konto nicht angelegt: "+err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (h *Hive) usersDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == h.auth.User(r) {
		httpErr(w, 400, "Das eigene Konto lässt sich nicht löschen.")
		return
	}
	var role string
	if h.st.db.QueryRow(`SELECT role FROM users WHERE username = ?`, name).Scan(&role) != nil {
		httpErr(w, 404, "unbekannter Benutzer")
		return
	}
	if role == "admin" {
		var admins int
		h.st.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&admins)
		if admins <= 1 {
			httpErr(w, 400, "Der letzte Admin lässt sich nicht löschen.")
			return
		}
	}
	h.st.db.Exec(`DELETE FROM auth_sessions WHERE username = ?`, name)
	h.st.db.Exec(`DELETE FROM users WHERE username = ?`, name)
	writeJSON(w, map[string]bool{"ok": true})
}
