//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Ein FIFO blockiert openRegular nicht, ein Verweis wird nicht geöffnet (Audit 4).
func TestOpenNoFollowFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "cowrie.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() {
		f, err := openNoFollow(fifo)
		if err == nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("open blockiert an einem FIFO")
	}
	if _, err := openRegular(fifo); err == nil {
		t.Fatal("FIFO als reguläre Datei geöffnet")
	}
	target := filepath.Join(dir, "hive.db")
	os.WriteFile(target, []byte("x"), 0o600)
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)
	if f, err := openNoFollow(link); err == nil {
		f.Close()
		t.Fatal("Verweis geöffnet")
	}
}
