//go:build !unix

package main

import "os"

func openNoFollow(path string) (*os.File, error) { return os.Open(path) }
