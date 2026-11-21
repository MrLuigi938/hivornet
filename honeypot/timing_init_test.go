package main

import "time"

// Die Tests der Protokolle sollen nicht auf die gestreuten Wartezeiten der Schein-Shell warten
// (timing.go); timing_test.go prüft die Standardfunktionen unmittelbar.
func init() {
	shellDelay = func(string) time.Duration { return 0 }
	mimicTarget = func(string) time.Duration { return 0 }
}
