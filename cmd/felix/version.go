package main

import (
	"fmt"
	"runtime"
)

var (
	Version   = "1.0.0"
	Release   = "FELIX 1.0 — First MVP"
	GitCommit = "dev"
	BuildTime = "unknown"
)

func runVersion(args []string) int {
	fmt.Println("Felix Security Auditor")
	fmt.Printf("Version:      %s\n", Version)
	fmt.Printf("Build:        %s\n", GitCommit)
	fmt.Printf("OS:           %s\n", runtime.GOOS)
	fmt.Printf("Architecture: %s\n", runtime.GOARCH)
	fmt.Printf("Platform:     %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Release:      %s\n", Release)
	fmt.Printf("Compiler:     %s\n", runtime.Version())
	return 0
}
