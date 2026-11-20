package main

// Tests zu den Funden des vierten Sicherheitsaudits (Ende-zu-Ende-Prüfung).

import (
	"strings"
	"testing"
)

// Kein CR/LF aus dem Pfad in Kopfzeilen: Vorher hängte der Tomcat-Köder über
// ?path=/x%0D%0ASet-Cookie:... eigene Kopfzeilen an die Antwort der Webshell.
func TestLureTomcatNoHeaderInjection(t *testing.T) {
	m := lureTest(t, "all")
	_, body, _ := lureDo(t, m, lureGet("/manager/text/deploy?path=/x%0D%0ASet-Cookie:hv_session=abc", basic("tomcat", "tomcat")))
	if strings.Contains(body, "\r") {
		t.Errorf("Pfad mit CR/LF angenommen: %q", body)
	}
	resp, _, _ := lureDo(t, m, lureGet("/x%0D%0ASet-Cookie:hv_session=abc/a"))
	for _, c := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(c, "hv_session") {
			t.Fatalf("eingeschleuster Cookie: %q", c)
		}
	}
}

func TestHasCtl(t *testing.T) {
	if !hasCtl("a\r\nb") || !hasCtl("a\x7f") || hasCtl("a\tb") || hasCtl("JSESSIONID=1; Path=/x") {
		t.Error("hasCtl")
	}
}
