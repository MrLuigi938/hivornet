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
