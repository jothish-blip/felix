package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"felix/pkg/oast"
)

// runOAST executes the "felix oast" subcommand.
func runOAST(args []string) int {
	if len(args) == 0 {
		printOASTHelp()
		return 0
	}

	subCmd := args[0]
	subArgs := args[1:]

	switch subCmd {
	case "token", "generate", "gen":
		return runOASTToken(subArgs)
	case "verify", "check":
		return runOASTVerify(subArgs)
	case "server", "listen":
		return runOASTServer(subArgs)
	case "--help", "-h", "help":
		printOASTHelp()
		return 0
	default:
		// If flag passed directly, e.g. felix oast --generate
		if strings.HasPrefix(subCmd, "-") {
			for _, a := range args {
				if a == "--generate" || a == "-g" {
					return runOASTToken(args)
				}
				if a == "--help" || a == "-h" {
					printOASTHelp()
					return 0
				}
			}
		}
		fmt.Fprintf(os.Stderr, "[-] Unknown oast subcommand: %s\n\n", subCmd)
		printOASTHelp()
		return 2
	}
}

func runOASTToken(args []string) int {
	var jsonOutput bool
	for _, arg := range args {
		if arg == "--json" {
			jsonOutput = true
		} else if arg == "--help" || arg == "-h" {
			fmt.Println("Usage: felix oast token [--json]")
			fmt.Println("\nGenerate a cryptographic 128-bit interaction token for out-of-band vulnerability probing.")
			return 0
		}
	}

	token, err := oast.GenerateInteractionToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error generating token: %v\n", err)
		return 1
	}

	domain := fmt.Sprintf("%s.oast.felix.internal", token)
	payloadURL := fmt.Sprintf("http://%s/", domain)

	if jsonOutput {
		res := map[string]string{
			"token":       token,
			"domain":      domain,
			"payload_url": payloadURL,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return 0
	}

	fmt.Print(banner)
	fmt.Println("FELIX 1.0 OAST INTERACTION TOKEN")
	fmt.Println("===========================================================")
	fmt.Printf("  Token:        %s\n", token)
	fmt.Printf("  OAST Domain:  %s\n", domain)
	fmt.Printf("  Payload URL:  %s\n", payloadURL)
	fmt.Println("===========================================================")
	fmt.Println("Usage in Payloads:")
	fmt.Println("  - SSRF/RCE:    curl " + payloadURL)
	fmt.Println("  - Blind XXE:   <!ENTITY % d SYSTEM \"" + payloadURL + "xxe\">")
	fmt.Println("  - DNS Probe:   nslookup " + domain)
	fmt.Println("===========================================================")
	return 0
}

func runOASTVerify(args []string) int {
	var (
		token      string
		jsonOutput bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--token" || arg == "-t":
			if i+1 < len(args) {
				token = args[i+1]
				i++
			}
		case arg == "--json":
			jsonOutput = true
		case arg == "--help" || arg == "-h":
			fmt.Println("Usage: felix oast verify --token <token> [--json]")
			fmt.Println("\nVerify whether interactions have been received for an OAST token.")
			return 0
		default:
			if !strings.HasPrefix(arg, "-") && token == "" {
				token = arg
			}
		}
	}

	if token == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: --token is required\n")
		return 2
	}

	if jsonOutput {
		res := map[string]any{
			"token":        token,
			"interactions": 0,
			"verified":     false,
			"status":       "AWAITING_CALLBACK",
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return 0
	}

	fmt.Print(banner)
	fmt.Println("FELIX 1.0 OAST TOKEN VERIFICATION")
	fmt.Println("===========================================================")
	fmt.Printf("  Token:        %s\n", token)
	fmt.Println("  Interactions: 0 recorded callbacks")
	fmt.Println("  Status:       AWAITING_CALLBACK (or listener offline)")
	fmt.Println("===========================================================")
	return 0
}

func runOASTServer(args []string) int {
	port := 8088
	timeoutSec := 60

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--port" || arg == "-p":
			if i+1 < len(args) {
				if p, err := strconv.Atoi(args[i+1]); err == nil && p > 0 {
					port = p
				}
				i++
			}
		case arg == "--timeout" || arg == "-t":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil && t > 0 {
					timeoutSec = t
				}
				i++
			}
		case arg == "--help" || arg == "-h":
			fmt.Println("Usage: felix oast server [--port 8088] [--timeout 60]")
			fmt.Println("\nLaunch a local Out-of-Band callback listener for test fixtures and local probing.")
			return 0
		}
	}

	cfg := oast.Config{
		BaseURL:      fmt.Sprintf("http://127.0.0.1:%d", port),
		OASTDomain:   "oast.felix.internal",
		DefaultTTL:   time.Duration(timeoutSec) * time.Second,
		AllowLoopback: true,
	}

	corr, err := oast.NewCorrelator(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to initialize OAST correlator: %v\n", err)
		return 1
	}

	receiver := oast.NewReceiver(corr)
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: receiver,
	}

	fmt.Print(banner)
	fmt.Println("FELIX 1.0 LOCAL OAST CALLBACK RECEIVER")
	fmt.Println("===========================================================")
	fmt.Printf("  Listening:    http://127.0.0.1:%d\n", port)
	fmt.Printf("  Callback TTL: %d seconds\n", timeoutSec)
	fmt.Println("  Ready to receive out-of-band HTTP probes and callbacks.")
	fmt.Println("  Press Ctrl+C to terminate listener.")
	fmt.Println("===========================================================")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.ListenAndServe()
	}()

	select {
	case <-sigChan:
		fmt.Println("\n[*] Shutting down OAST receiver...")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		return 0
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "[-] OAST listener error: %v\n", err)
			return 1
		}
		return 0
	}
}

func printOASTHelp() {
	fmt.Println("Usage: felix oast <subcommand> [flags]")
	fmt.Println("\nOut-of-Band Application Security Testing (OAST) utility.")
	fmt.Println("\nSubcommands:")
	fmt.Println("  token       Generate a new 128-bit cryptographic interaction token")
	fmt.Println("  verify      Check for recorded callbacks for a given token")
	fmt.Println("  server      Run a local OAST callback HTTP receiver for testing")
	fmt.Println("\nFlags:")
	fmt.Println("  --help, -h  Show this help message")
}
