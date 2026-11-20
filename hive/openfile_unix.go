//go:build unix

package main

import (
	"os"
	"syscall"
)

// openNoFollow öffnet nur lesend, folgt keinem Verweis an der letzten Stelle und blockiert
// nicht an einem FIFO (Audit 4): Zwischen Lstat und Open konnte ein übernommenes Cowrie die
// Datei gegen ein FIFO tauschen; open() hing dann dauerhaft und der Hive las nichts mehr.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
