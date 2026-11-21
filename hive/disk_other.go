//go:build !linux && !windows

package main

func diskFree(string) int64 { return -1 }

func diskTotalFree(string) (int64, int64) { return 0, 0 }
