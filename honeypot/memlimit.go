package main

// Weiche Speichergrenze für die Speicherbereinigung (M4 des dritten Audits). Der Sensor läuft
// mit einer harten Grenze (Docker mem_limit 192 MB, Pi MemoryMax=192M). Ohne Angabe weiß die
// Go-Laufzeit davon nichts und räumt erst bei doppelter Heap-Größe auf; unter Last wird der
// Prozess dann beendet, bevor die Bereinigung greift. Ist GOMEMLIMIT nicht gesetzt, gilt
// deshalb 85 % der cgroup-Grenze.

import (
	"log"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

// cgroupFiles: cgroup v2, dann v1.
var cgroupFiles = []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"}

// cgroupLimit liest die harte Speichergrenze (0 = keine oder unbekannt).
func cgroupLimit(read func(string) ([]byte, error)) int64 {
	for _, f := range cgroupFiles {
		b, err := read(f)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(b))
		if s == "max" {
			return 0
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 || n >= 1<<50 { // v1 meldet ohne Grenze eine riesige Zahl
			return 0
		}
		return n
	}
	return 0
}

// softMemLimit: Wert für debug.SetMemoryLimit (0 = nichts setzen).
func softMemLimit(getenv func(string) string, read func(string) ([]byte, error)) int64 {
	if getenv("GOMEMLIMIT") != "" { // ausdrücklich gesetzt: gilt schon
		return 0
	}
	if n := cgroupLimit(read); n >= 32<<20 {
		return n / 100 * 85
	}
	return 0
}

func applyMemLimit() {
	if n := softMemLimit(os.Getenv, os.ReadFile); n > 0 {
		debug.SetMemoryLimit(n)
		log.Printf("Speichergrenze für die Speicherbereinigung: %d MB", n>>20)
	}
}
