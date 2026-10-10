package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/operator"
)

func runOperator(args []string) int {
	fs := flag.NewFlagSet("felix operator", flag.ContinueOnError)

	var (
		host       string
		port       int
		operatorID string
		token      string
		dbPath     string
		noOpen     bool
	)

	fs.StringVar(&host, "host", "127.0.0.1", "Host address to bind (must be loopback: 127.0.0.1 or ::1)")
	fs.IntVar(&port, "port", 8383, "Port number to bind")
	fs.StringVar(&operatorID, "operator-id", "", "Active operator identifier")
	fs.StringVar(&token, "token", "", "Operator session token (auto-generated if empty)")
	fs.StringVar(&dbPath, "db", "", "Path to SQLite database")
	fs.BoolVar(&noOpen, "no-open", false, "Do not automatically launch web browser")

	fs.Usage = func() {
		fmt.Println("Usage: felix operator [options]")
		fmt.Println("\nLaunch the local-first Felix Operator Console.")
		fmt.Println("Provides authorized assessment management, scan orchestration, finding review curation,")
		fmt.Println("Commercial Report 2.0 generation, and report delivery tracking.")
		fmt.Println("\nOptions:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	// Security validation: host must be loopback
	h := strings.ToLower(strings.TrimSpace(host))
	if h != "127.0.0.1" && h != "localhost" && h != "::1" && h != "[::1]" && h != "ip6-localhost" {
		fmt.Fprintf(os.Stderr, "[-] Security refusal: Felix Operator Console must only bind to a loopback address (127.0.0.1 or ::1), got %q\n", host)
		return 2
	}

	// Database setup
	if dbPath == "" {
		var err error
		dbPath, err = assessment.DefaultDBPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to determine default database path: %v\n", err)
			return 1
		}
	}

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open database at %s: %v\n", dbPath, err)
		return 1
	}
	defer store.Close()

	if operatorID == "" {
		operatorID = os.Getenv("USER")
		if operatorID == "" {
			operatorID = os.Getenv("USERNAME")
		}
		if operatorID == "" {
			operatorID = "operator"
		}
	}

	cfg := operator.Config{
		ListenHost: host,
		ListenPort: port,
		OperatorID: operatorID,
		Token:      token,
		Store:      store,
		Version:    "2.0.0",
	}

	srv, err := operator.NewServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to initialize operator server: %v\n", err)
		return 1
	}

	consoleURL := srv.URL()

	fmt.Println("===========================================================")
	fmt.Println("  FELIX OPERATOR :: Authorized Cybersecurity Console")
	fmt.Println("  \"Commercial Assessment Curation & Delivery Engine\"")
	fmt.Println("===========================================================")
	fmt.Printf("[+] Operator Session Active:\n")
	fmt.Printf("    • Listener:        %s:%d (Strict Loopback)\n", host, port)
	fmt.Printf("    • Active Operator: %s\n", operatorID)
	fmt.Printf("    • Database:        %s\n", dbPath)
	fmt.Printf("    • Console URL:     %s\n\n", consoleURL)
	fmt.Println("[+] Press Ctrl+C to gracefully terminate the console session.")

	if !noOpen {
		go func() {
			time.Sleep(300 * time.Millisecond)
			openBrowser(consoleURL)
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.Start(ctx); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "[-] Operator server error: %v\n", err)
		return 1
	}

	fmt.Println("\n[*] Felix Operator session shut down cleanly.")
	return 0
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
