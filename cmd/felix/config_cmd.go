package main

import (
	"fmt"
	"os"

	"felix/pkg/config"
)

func runConfig(args []string) int {
	if len(args) > 0 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		printConfigHelp()
		return 0
	}
	if len(args) == 0 || args[0] == "show" {
		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Configuration error: %v\n", err)
			return 2
		}
		p, _ := config.Path()
		fmt.Printf("Felix Configuration (%s):\n", p)
		fmt.Printf("  timeout:      %d seconds\n", cfg.Timeout)
		fmt.Printf("  concurrency:  %d workers\n", cfg.Concurrency)
		fmt.Printf("  scope:        %s\n", cfg.Scope)
		fmt.Printf("  max_size_mb:  %d MB\n", cfg.MaxSizeMB)
		fmt.Printf("  user_agent:   %s\n", cfg.UserAgent)
		fmt.Printf("  max_assets:   %d\n", cfg.MaxAssets)
		fmt.Printf("  max_depth:    %d\n", cfg.MaxDepth)
		fmt.Printf("  max_retries:  %d\n", cfg.MaxRetries)
		fmt.Printf("  retry_delay:  %d ms\n", cfg.RetryDelayMs)
		fmt.Printf("  max_redirects: %d\n", cfg.MaxRedirects)
		fmt.Printf("  insecure_skip_verify: %t\n", cfg.InsecureSkipVerify)
		fmt.Printf("  allow_private_ips:    %t\n", cfg.AllowPrivateIPs)
		fmt.Printf("  allow_loopback:       %t\n", cfg.AllowLoopback)
		fmt.Printf("  active_verification:  %t\n", cfg.ActiveVerification)
		return 0
	}

	switch args[0] {
	case "get":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: felix config get <key>\n")
			return 2
		}
		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Configuration error: %v\n", err)
			return 2
		}
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
		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Configuration error: %v\n", err)
			return 2
		}
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

func printConfigHelp() {
	fmt.Println("Usage:")
	fmt.Println("  felix config <action> [arguments]")
	fmt.Println("\nActions:")
	fmt.Println("  show              Display active configuration settings")
	fmt.Println("  get <key>         Get value of a configuration setting")
	fmt.Println("  set <key> <val>   Set value of a configuration setting")
	fmt.Println("  path              Display path to configuration file")
	fmt.Println("  reset             Restore default configuration")
}
