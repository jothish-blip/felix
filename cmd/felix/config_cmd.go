package main

import (
	"fmt"
	"os"

	"felix/pkg/config"
)

func runConfig(args []string) int {
	if len(args) == 0 || args[0] == "show" {
		cfg := config.Load()
		p, _ := config.Path()
		fmt.Printf("Felix Configuration (%s):\n", p)
		fmt.Printf("  timeout:      %d seconds\n", cfg.Timeout)
		fmt.Printf("  concurrency:  %d workers\n", cfg.Concurrency)
		fmt.Printf("  scope:        %s\n", cfg.Scope)
		fmt.Printf("  max_size_mb:  %d MB\n", cfg.MaxSizeMB)
		fmt.Printf("  user_agent:   %s\n", cfg.UserAgent)
		return 0
	}

	switch args[0] {
	case "get":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: felix config get <key>\n")
			return 2
		}
		cfg := config.Load()
		val, err := cfg.Get(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
			return 2
		}
		fmt.Println(val)
		return 0

	case "set":
		if len(args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: felix config set <key> <value>\n")
			return 2
		}
		cfg := config.Load()
		if err := cfg.Set(args[1], args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
			return 2
		}
		if err := config.Save(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to save config: %v\n", err)
			return 2
		}
		fmt.Printf("[+] Set %s = %s\n", args[1], args[2])
		return 0

	case "path":
		p, err := config.Path()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to determine config path: %v\n", err)
			return 2
		}
		fmt.Println(p)
		return 0

	case "reset":
		if err := config.Reset(); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to reset config: %v\n", err)
			return 2
		}
		fmt.Println("[+] Restored default configuration.")
		return 0

	default:
		fmt.Fprintf(os.Stderr, "Unknown config action %q. Use: show, get, set, path, reset\n", args[0])
		return 2
	}
}
