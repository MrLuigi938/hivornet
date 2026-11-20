package main

// Signierte Veröffentlichungen. Der Release-Workflow signiert SHA256SUMS mit einem
// Ed25519-Schlüssel, dessen privater Teil nur als GitHub-Secret (HIVORNET_SIGNING_KEY)
// existiert. Der öffentliche Teil steht hier im Programm. Der Pi-Updater (hivornet-update)
// lässt das bereits installierte Programm die Signatur prüfen, bevor er ein Paket einspielt:
// Wer nur die Veröffentlichung auf GitHub verändert (Konto übernommen, Paket ausgetauscht),
// kann keine passende Signatur erzeugen.
//
//   hive verify-release SHA256SUMS SHA256SUMS.sig
//   hive sign-release SHA256SUMS SHA256SUMS.sig   (nur im Release-Workflow; privater Schlüssel
//                                                 als PEM in HIVORNET_SIGNING_KEY)
//
// SHA256SUMS.sig enthält die 64 Byte lange Ed25519-Signatur in Base64 (eine Zeile).

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// releaseKeys: erlaubte öffentliche Schlüssel (Base64). Beim Wechsel des Schlüssels kommt der
// neue zuerst dazu; der alte fliegt erst heraus, wenn alle Installationen den neuen kennen.
var releaseKeys = []string{
	"Jx+Ahnu1RLChrAddv4JbzAocfwqKCBlxkOTp7/2wwOg=", // erster Schlüssel, November 2026
}

func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s ist zu groß", path)
	}
	return b, nil
}

// verifyRelease prüft die Signatur von sums gegen releaseKeys.
func verifyRelease(sumsPath, sigPath string) error {
	sums, err := readLimited(sumsPath, 64<<10)
	if err != nil {
		return err
	}
	raw, err := readLimited(sigPath, 1024)
	if err != nil {
		return fmt.Errorf("Signatur fehlt: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("Signatur unlesbar")
	}
	for _, k := range releaseKeys {
		pub, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pub), sums, sig) {
			return nil
		}
	}
	return errors.New("Signatur passt zu keinem bekannten Schlüssel")
}

// signRelease signiert sums mit dem privaten Schlüssel (PEM, PKCS#8) und schreibt sig. Die
// Signatur wird gleich gegen releaseKeys geprüft: Passt das Secret nicht zum Schlüssel im
// Programm, scheitert die Veröffentlichung statt Pakete zu liefern, die kein Pi annimmt.
func signRelease(sumsPath, sigPath string, pemKey []byte) error {
	blk, _ := pem.Decode(pemKey)
	if blk == nil {
		return errors.New("privater Schlüssel fehlt oder ist kein PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return fmt.Errorf("privater Schlüssel unlesbar: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return errors.New("kein Ed25519-Schlüssel")
	}
	sums, err := readLimited(sumsPath, 64<<10)
	if err != nil {
		return err
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, sums)) + "\n"
	if err := os.WriteFile(sigPath, []byte(sig), 0o644); err != nil {
		return err
	}
	return verifyRelease(sumsPath, sigPath)
}
