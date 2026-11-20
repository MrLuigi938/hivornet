package main

// Zeitzone für alle Uhrzeiten, die der Hive selbst in Texte schreibt (Angriffsbericht,
// Wochenbericht, KI-Texte, Fehlermeldungen) und für seine Zeitpläne ("montags ab 8 Uhr").
//
// Der Raspberry Pi und der Docker-Container laufen meist ohne gesetzte Zeitzone, Go nimmt
// dann UTC. Die Web-UI rechnet im Browser selbst um; nur serverseitige Texte brauchen
// diese Einstellung. Reihenfolge: Einstellung "Zeitzone" (IANA-Name, z. B. Europe/Berlin),
// sonst die Umgebungsvariable TZ, sonst UTC. Die Zonendaten sind eingebettet, damit es
// auch im Container ohne /usr/share/zoneinfo geht.

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
	_ "time/tzdata"
)

var hiveZone atomic.Pointer[time.Location]

// hiveLoc: die eingestellte Zeitzone (nie nil).
func hiveLoc() *time.Location {
	if l := hiveZone.Load(); l != nil {
		return l
	}
	return envZone()
}

// hiveNow: jetzt in der eingestellten Zeitzone (für Tagesgrenzen und Zeitpläne).
func hiveNow() time.Time { return time.Now().In(hiveLoc()) }

// envZone: Zeitzone aus TZ, sonst UTC.
func envZone() *time.Location {
	if tz := strings.TrimPrefix(strings.TrimSpace(os.Getenv("TZ")), ":"); tz != "" {
		if l, err := time.LoadLocation(tz); err == nil {
			return l
		}
	}
	return time.UTC
}

// setHiveZone übernimmt die Einstellung; leer heißt TZ bzw. UTC.
func setHiveZone(name string) {
	if l, err := loadZone(name); err == nil && l != nil {
		hiveZone.Store(l)
		return
	}
	hiveZone.Store(envZone())
}

// loadZone prüft einen IANA-Namen. Leer liefert nil (= Vorgabe).
func loadZone(name string) (*time.Location, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, nil
	}
	// "Local" hinge vom Rechner ab, Pfade und Steuerzeichen haben im Namen nichts zu suchen
	if len(name) > 64 || name == "Local" || strings.ContainsAny(name, " \\\r\n") || strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
		return nil, fmt.Errorf("Zeitzone: bitte einen Namen wie Europe/Berlin angeben")
	}
	l, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("Zeitzone „%s“ ist unbekannt (Beispiel: Europe/Berlin)", name)
	}
	return l, nil
}

// zoneLabel: Name der wirksamen Zeitzone für die Anzeige.
func zoneLabel() string { return hiveLoc().String() }
