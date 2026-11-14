//go:build !linux

package main

func diskFree(string) int64 { return -1 }
