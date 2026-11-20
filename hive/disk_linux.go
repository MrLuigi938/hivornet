//go:build linux

package main

import (
	"path/filepath"
	"syscall"
)

func diskFree(path string) int64 {
	var st syscall.Statfs_t
	if syscall.Statfs(filepath.Dir(path), &st) != nil {
		return -1
	}
	return int64(st.Bavail) * int64(st.Bsize)
}

// diskTotalFree: Größe und freier Platz des Dateisystems der Datenbank (Hardware-Monitor).
func diskTotalFree(path string) (total, free int64) {
	var st syscall.Statfs_t
	if syscall.Statfs(filepath.Dir(path), &st) != nil {
		return 0, 0
	}
	return int64(st.Blocks) * int64(st.Bsize), int64(st.Bavail) * int64(st.Bsize)
}
