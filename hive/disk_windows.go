//go:build windows

package main

// Nur für die Entwicklung unter Windows: Größe und freier Platz des Laufwerks der
// Datenbank, damit Grenze und Obergrenze (dblimit.go) wie auf dem Pi rechnen.

import (
	"path/filepath"
	"syscall"
	"unsafe"
)

var procDiskFree = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

func diskTotalFree(path string) (total, free int64) {
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return 0, 0
	}
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return 0, 0
	}
	var avail, tot, all uint64
	if r, _, _ := procDiskFree.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&avail)), uintptr(unsafe.Pointer(&tot)), uintptr(unsafe.Pointer(&all))); r == 0 {
		return 0, 0
	}
	return int64(tot), int64(avail)
}

func diskFree(path string) int64 {
	if total, free := diskTotalFree(path); total > 0 {
		return free
	}
	return -1
}
