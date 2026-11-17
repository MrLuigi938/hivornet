package main

import (
	"bytes"
	"io"
)

// readN liest genau n Bytes. Speicher wird erst belegt, wenn die Daten wirklich kommen:
// Ein Angreifer, der eine große Länge ankündigt und dann nichts schickt, belegt so fast
// nichts. Kleine Nachrichten werden direkt gelesen.
func readN(r io.Reader, n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	if n <= 4096 {
		b := make([]byte, n)
		_, err := io.ReadFull(r, b)
		return b, err
	}
	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, r, int64(n)); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return buf.Bytes(), err
	}
	return buf.Bytes(), nil
}
