package main

import (
	"fmt"
	"runtime"
)

const (
	Version = "1.0.0"
	Release = "Phase 1 Productization"
)

func runVersion(args []string) int {
	fmt.Println("Felix Security Auditor")
	fmt.Printf("Version:  %s\n", Version)
	fmt.Printf("Release:  %s\n", Release)
	fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Compiler: %s\n", runtime.Version())
	return 0
}
