package main

import (
	"testing"
	"time"
)

func TestHiveZone(t *testing.T) {
	t.Setenv("TZ", "")
	defer setHiveZone("")
	setHiveZone("")
	if hiveLoc() != time.UTC {
		t.Fatalf("ohne Einstellung und TZ: %v", hiveLoc())
	}
	t.Setenv("TZ", "America/New_York")
	setHiveZone("")
	if hiveLoc().String() != "America/New_York" {
		t.Fatalf("TZ nicht übernommen: %v", hiveLoc())
	}
	setHiveZone("Europe/Berlin") // Einstellung schlägt TZ
	ts := time.Date(2026, 11, 20, 23, 51, 0, 0, time.UTC)
	if got := ts.In(hiveLoc()).Format("02.01. 15:04"); got != "21.11. 00:51" {
		t.Fatalf("Berlin: %s", got)
	}
	for _, bad := range []string{"Local", "../../etc/passwd", "Mond/Krater", "Europe/Ber\nlin","/etc/localtime"} {
		if _, err := loadZone(bad); err == nil {
			t.Errorf("%q müsste abgelehnt werden", bad)
		}
	}
	x := defaultExtras()
	x.TimeZone = " Asia/Tokyo "
	if err := x.Validate(); err != nil || x.TimeZone != "Asia/Tokyo" {
		t.Fatalf("Validate: %v %q", err, x.TimeZone)
	}
	x.TimeZone = "Nirgendwo/Stadt"
	if err := x.Validate(); err == nil {
		t.Fatal("unbekannte Zone angenommen")
	}
}
