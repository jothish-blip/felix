package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"felix/pkg/crawler"
	"felix/pkg/secrets"
)

// runSecrets executes the "felix secrets" subcommand.
func runSecrets(args []string) int {
	var (
		filePath      string
		targetURL     string
		rawString     string
		jsonOutput    bool
		outputPath    string
		allowLoopback bool
		allowPrivate  bool
		verbose       bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--file" || arg == "-f":
			if i+1 < len(args) {
				filePath = args[i+1]
				i++
			}
		case arg == "--url" || arg == "-u":
			if i+1 < len(args) {
				targetURL = args[i+1]
				i++
			}
		case arg == "--string" || arg == "-s":
			if i+1 < len(args) {
				rawString = args[i+1]
				i++
			}
		case arg == "--output" || arg == "-o":
			if i+1 < len(args) {
				outputPath = args[i+1]
				i++
			}
		case arg == "--json":
			jsonOutput = true
		case arg == "--allow-loopback":
			allowLoopback = true
		case arg == "--allow-private":
			allowPrivate = true
		case arg == "--verbose" || arg == "-v":
			verbose = true
		case arg == "--help" || arg == "-h":
			printSecretsHelp()
			return 0
		default:
			if !strings.HasPrefix(arg, "-") {
				if filePath == "" && targetURL == "" && rawString == "" {
					if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
						targetURL = arg
					} else if fi, err := os.Stat(arg); err == nil && !fi.IsDir() {
						filePath = arg
					} else if fi, err := os.Stat(arg); err == nil && fi.IsDir() {
						filePath = arg
					} else {
						rawString = arg
					}
				}
			}
		}
	}

	if filePath == "" && targetURL == "" && rawString == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: target file, URL, or string is required\n\n")
		printSecretsHelp()
		return 2
	}

	detector := secrets.NewDetector()
	var allFindings []secrets.SecretFinding
	scannedItems := 0

	// 1. File or directory scan
	if filePath != "" {
		info, err := os.Stat(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error accessing file %q: %v\n", filePath, err)
			return 2
		}

		if info.IsDir() {
			err = filepath.Walk(filePath, func(p string, fi os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return nil
				}
				if fi.IsDir() {
					name := fi.Name()
					if name == ".git" || name == "node_modules" || name == "vendor" || name == ".svn" {
						return filepath.SkipDir
					}
					return nil
				}
				if fi.Size() > 10*1024*1024 { // Skip files > 10MB
					return nil
				}
				content, readErr := os.ReadFile(p)
				if readErr != nil {
					return nil
				}
				scannedItems++
				findings := detector.ScanContent(p, content)
				allFindings = append(allFindings, findings...)
				return nil
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Error scanning directory: %v\n", err)
				return 2
			}
		} else {
			content, readErr := os.ReadFile(filePath)
			if readErr != nil {
				fmt.Fprintf(os.Stderr, "[-] Error reading file %q: %v\n", filePath, readErr)
				return 2
			}
			scannedItems++
			allFindings = detector.ScanContent(filePath, content)
		}
	}

	// 2. URL scan
	if targetURL != "" {
		parsed, err := url.Parse(targetURL)
		if err != nil || parsed.Host == "" {
			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				targetURL = "https://" + targetURL
				parsed, err = url.Parse(targetURL)
			}
		}
		if err != nil || parsed.Host == "" {
			fmt.Fprintf(os.Stderr, "[-] Error: invalid target URL %q\n", targetURL)
			return 2
		}

		host := parsed.Hostname()
		ips, _ := net.LookupIP(host)
		if len(ips) > 0 {
			for _, ip := range ips {
				if prohibited, reason := crawler.ProhibitedIPReason(ip, allowLoopback || os.Getenv("FELIX_ALLOW_LOOPBACK") == "true", allowPrivate || os.Getenv("FELIX_ALLOW_PRIVATE") == "true"); prohibited {
					fmt.Fprintf(os.Stderr, "[-] Error: destination %s resolves to prohibited address (%s: %s). Use --allow-loopback or --allow-private to permit.\n", targetURL, ip.String(), reason)
					return 2
				}
			}
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: crawler.NewSafeDialContext(crawler.SafeDialerOptions{
				Timeout:         10 * time.Second,
				AllowLoopback:   allowLoopback || os.Getenv("FELIX_ALLOW_LOOPBACK") == "true",
				AllowPrivateIPs: allowPrivate || os.Getenv("FELIX_ALLOW_PRIVATE") == "true",
			}),
		}
		client := &http.Client{Transport: tr, Timeout: 15 * time.Second}

		resp, err := client.Get(targetURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error fetching URL %q: %v\n", targetURL, err)
			return 2
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error reading response: %v\n", err)
			return 2
		}
		scannedItems++
		allFindings = detector.ScanContent(targetURL, bodyBytes)
	}

	// 3. Raw string scan
	if rawString != "" {
		scannedItems++
		findings := detector.ScanContent("inline-string", []byte(rawString))
		allFindings = append(allFindings, findings...)
	}

	// Output Formatting
	if jsonOutput {
		data, err := json.MarshalIndent(allFindings, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] JSON encoding error: %v\n", err)
			return 2
		}
		if outputPath != "" {
			if err := os.WriteFile(outputPath, data, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Error writing to output file: %v\n", err)
				return 2
			}
		} else {
			fmt.Println(string(data))
		}
		if len(allFindings) > 0 {
			return 1
		}
		return 0
	}

	fmt.Print(banner)
	fmt.Println("FELIX 1.0 SECRETS & CREDENTIAL SCANNER")
	fmt.Println("===========================================================")
	if filePath != "" {
		fmt.Printf("  Target Path:   %s\n", filePath)
	}
	if targetURL != "" {
		fmt.Printf("  Target URL:    %s\n", targetURL)
	}
	fmt.Printf("  Items Scanned: %d\n", scannedItems)
	fmt.Printf("  Secrets Found: %d\n", len(allFindings))
	fmt.Println("===========================================================")

	if len(allFindings) == 0 {
		fmt.Println("[+] No secrets, API keys, or private tokens detected.")
		return 0
	}

	for i, f := range allFindings {
		fmt.Printf("[%d] [%s] %s\n", i+1, f.Severity, f.Title)
		fmt.Printf("    Origin:      %s (Line: %d)\n", f.FileOrigin, f.LineNumber)
		fmt.Printf("    Redacted:    %s\n", f.Redacted)
		fmt.Printf("    Confidence:  %s\n", f.Confidence)
		if verbose && f.Evidence != "" {
			fmt.Printf("    Evidence:    %s\n", f.Evidence)
		}
		fmt.Printf("    Fingerprint: %s\n", f.Fingerprint)
		fmt.Println()
	}

	if outputPath != "" {
		data, err := json.MarshalIndent(allFindings, "", "  ")
		if err == nil {
			_ = os.WriteFile(outputPath, data, 0644)
			fmt.Printf("[+] Findings exported to: %s\n", outputPath)
		}
	}

	return 1
}

func printSecretsHelp() {
	fmt.Println("Usage: felix secrets [flags] [target]")
	fmt.Println("\nScan files, directories, web URLs, or strings for high-entropy secrets and API tokens.")
	fmt.Println("\nFlags:")
	fmt.Println("  --file, -f <path>      Scan a local file or directory recursively")
	fmt.Println("  --url, -u <url>        Fetch and scan web page content and scripts")
	fmt.Println("  --string, -s <text>    Scan a raw text string")
	fmt.Println("  --output, -o <file>    Save findings to a JSON file")
	fmt.Println("  --json                 Output findings formatted as JSON to stdout")
	fmt.Println("  --allow-loopback       Allow scanning loopback/localhost URLs (testing only)")
	fmt.Println("  --allow-private        Allow scanning RFC 1918 private IP URLs")
	fmt.Println("  --verbose, -v          Show raw evidence snippets")
	fmt.Println("  --help, -h             Show this help message")
}
