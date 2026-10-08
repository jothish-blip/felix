package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"felix/pkg/crawler"
)

const banner = `
===========================================================
  FELIX :: Web Security Auditing CLI
  "Attackers rely on luck. Felix leaves them zero."
===========================================================
`

func main() {
	var (
		concurrency int
		timeoutSec  int
		inputFile   string
		verbose     bool
	)

	flag.IntVar(&concurrency, "c", 10, "Number of concurrent workers")
	flag.IntVar(&timeoutSec, "t", 10, "HTTP timeout in seconds per target")
	flag.StringVar(&inputFile, "l", "", "Path to file containing target URLs (one per line)")
	flag.BoolVar(&verbose, "v", false, "Enable verbose output")
	flag.Usage = func() {
		fmt.Print(banner)
		fmt.Printf("Usage: felix [options] <target-url>\n\nOptions:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	var targets []string

	// Load targets from argument
	if flag.NArg() > 0 {
		targets = append(targets, flag.Args()...)
	}

	// Load targets from file if specified
	if inputFile != "" {
		fileTargets, err := readLines(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to read target file: %v\n", err)
			os.Exit(1)
		}
		targets = append(targets, fileTargets...)
	}

	if len(targets) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	fmt.Print(banner)
	fmt.Printf("[*] Loaded %d target(s) | Concurrency: %d | Timeout: %ds\n\n", len(targets), concurrency, timeoutSec)

	cfg := crawler.Config{
		Concurrency: concurrency,
		Timeout:     time.Duration(timeoutSec) * time.Second,
	}
	c := crawler.New(cfg)

	// Graceful cancellation on SIGINT/SIGTERM
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	results := c.CrawlConcurrently(ctx, targets)

	totalScripts := 0
	for res := range results {
		if res.Err != nil {
			fmt.Printf("[-] [%s] Error: %v\n", res.Target, res.Err)
			continue
		}

		fmt.Printf("[+] [%s] Extracted %d script bundles:\n", res.Target, len(res.Scripts))
		for _, s := range res.Scripts {
			fmt.Printf("    -> %s\n", s)
			totalScripts++
		}
		fmt.Println()
	}

	fmt.Printf("[*] Scan complete. %d total scripts discovered across %d targets.\n", totalScripts, len(targets))
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
