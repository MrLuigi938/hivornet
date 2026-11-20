package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyRelease(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	old := releaseKeys
	releaseKeys = []string{"kaputt", base64.StdEncoding.EncodeToString(pub)}
	t.Cleanup(func() { releaseKeys = old })
	dir := t.TempDir()
	sums := []byte("abc123  hivornet-v1.0.0-linux-arm64.tar.gz\n")
	p := func(n string) string { return filepath.Join(dir, n) }
	os.WriteFile(p("SHA256SUMS"), sums, 0o644)
	write := func(sig []byte) {
		os.WriteFile(p("SHA256SUMS.sig"), []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644)
	}

	write(ed25519.Sign(priv, sums))
	if err := verifyRelease(p("SHA256SUMS"), p("SHA256SUMS.sig")); err != nil {
		t.Fatalf("gültige Signatur abgelehnt: %v", err)
	}
	// fremder Schlüssel
	write(ed25519.Sign(other, sums))
	if verifyRelease(p("SHA256SUMS"), p("SHA256SUMS.sig")) == nil {
		t.Error("fremde Signatur angenommen")
	}
	// veränderte Prüfsummen
	write(ed25519.Sign(priv, sums))
	os.WriteFile(p("SHA256SUMS"), []byte("def456  hivornet-v1.0.0-linux-arm64.tar.gz\n"), 0o644)
	if verifyRelease(p("SHA256SUMS"), p("SHA256SUMS.sig")) == nil {
		t.Error("veränderte Prüfsummen angenommen")
	}
	// fehlende und kaputte Signatur
	os.Remove(p("SHA256SUMS.sig"))
	if verifyRelease(p("SHA256SUMS"), p("SHA256SUMS.sig")) == nil {
		t.Error("fehlende Signatur angenommen")
	}
	os.WriteFile(p("SHA256SUMS.sig"), []byte("!!!"), 0o644)
	if verifyRelease(p("SHA256SUMS"), p("SHA256SUMS.sig")) == nil {
		t.Error("kaputte Signatur angenommen")
	}
}

func TestReleaseKeysValid(t *testing.T) {
	for _, k := range releaseKeys {
		if b, err := base64.StdEncoding.DecodeString(k); err != nil || len(b) != ed25519.PublicKeySize {
			t.Errorf("ungültiger Schlüssel %q", k)
		}
	}
}

func TestSignRelease(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	old := releaseKeys
	t.Cleanup(func() { releaseKeys = old })
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	dir := t.TempDir()
	sums, sig := filepath.Join(dir, "SHA256SUMS"), filepath.Join(dir, "SHA256SUMS.sig")
	os.WriteFile(sums, []byte("abc  x.tar.gz\n"), 0o644)

	// Secret passt nicht zum Schlüssel im Programm: Fehler
	if signRelease(sums, sig, key) == nil {
		t.Error("Signatur mit unbekanntem Schlüssel als gültig gemeldet")
	}
	releaseKeys = []string{base64.StdEncoding.EncodeToString(pub)}
	if err := signRelease(sums, sig, key); err != nil {
		t.Fatalf("signRelease: %v", err)
	}
	if err := verifyRelease(sums, sig); err != nil {
		t.Errorf("verifyRelease: %v", err)
	}
	for _, bad := range [][]byte{nil, []byte("kein pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})} {
		if signRelease(sums, sig, bad) == nil {
			t.Errorf("Schlüssel %q angenommen", bad)
		}
	}
}
