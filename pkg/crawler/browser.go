package crawler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// Common browser discovery errors.
var (
	ErrNoBrowserFound       = errors.New("no supported headless browser executable found")
	ErrBrowserTimeout       = errors.New("headless browser execution timed out")
	ErrOutOfScopeNavigation = errors.New("browser navigation blocked: target is out of scope")
)

// BrowserDiscoveryOptions controls dynamic headless browser execution.
type BrowserDiscoveryOptions struct {
	Enabled        bool                   `json:"enabled"`
	BrowserBinary  string                 `json:"browser_binary,omitempty"`
	Timeout        time.Duration          `json:"timeout,omitempty"`
	WaitUntilReady time.Duration          `json:"wait_until_ready,omitempty"`
	DisableSandbox bool                   `json:"disable_sandbox,omitempty"` // Explicit opt-in for containerized environments
	Driver         BrowserDiscoveryDriver `json:"-"`
}

// DynamicEndpoint represents a route, link, script, or API request discovered dynamically.
type DynamicEndpoint struct {
	URL        string    `json:"url"`
	Type       AssetType `json:"type"` // e.g. AssetJavaScript, AssetUnknown, "route", "api"
	Method     string    `json:"method,omitempty"`
	InScope    bool      `json:"in_scope"`
	Provenance string    `json:"provenance"` // ProvenanceBrowser
	Inferred   bool      `json:"inferred"`   // false for rendered DOM elements, true for regex/script pattern matches
}

// BrowserDiscoveryResult represents the outcome of dynamic browser discovery.
type BrowserDiscoveryResult struct {
	Endpoints    []DynamicEndpoint `json:"endpoints"`
	RenderedHTML string            `json:"rendered_html,omitempty"`
	Inconclusive bool              `json:"inconclusive"`
	Reason       string            `json:"reason,omitempty"`
	Duration     time.Duration     `json:"duration"`
	BinaryUsed   string            `json:"binary_used,omitempty"`
}

// BrowserDiscoveryDriver defines the interface for headless browser discovery.
type BrowserDiscoveryDriver interface {
	Discover(ctx context.Context, targetURL string, opts BrowserDiscoveryOptions, scope *Scope) (*BrowserDiscoveryResult, error)
}

// HeadlessBrowserDriver is the native, zero-runtime-dependency browser discovery driver.
// It executes system Chromium-based browsers (Chrome, Edge, Chromium) via bounded CLI headless flags.
type HeadlessBrowserDriver struct{}

// NewHeadlessBrowserDriver creates a new HeadlessBrowserDriver.
func NewHeadlessBrowserDriver() *HeadlessBrowserDriver {
	return &HeadlessBrowserDriver{}
}

// Discover navigates to targetURL using the local headless browser, extracts DOM-rendered assets,
// intercepts API references, validates scopes, and returns dynamic findings with browser provenance.
func (d *HeadlessBrowserDriver) Discover(ctx context.Context, targetURL string, opts BrowserDiscoveryOptions, scope *Scope) (*BrowserDiscoveryResult, error) {
	start := time.Now()
	res := &BrowserDiscoveryResult{
		Endpoints: make([]DynamicEndpoint, 0),
	}

	// 1. Validate initial scope
	if scope != nil && !scope.IsAllowed(targetURL) {
		res.Inconclusive = true
		res.Reason = fmt.Sprintf("target %s blocked: out of approved crawl scope", targetURL)
		res.Duration = time.Since(start)
		return res, ErrOutOfScopeNavigation
	}

	// 2. Locate browser executable
	binPath, err := FindBrowserBinary(opts.BrowserBinary)
	if err != nil {
		res.Inconclusive = true
		res.Reason = fmt.Sprintf("dynamic discovery skipped: %v", err)
		res.Duration = time.Since(start)
		return res, nil
	}
	res.BinaryUsed = binPath

	// 3. Execution timeout
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Virtual time budget in milliseconds for script execution
	budgetMs := 1500
	if opts.WaitUntilReady > 0 {
		budgetMs = int(opts.WaitUntilReady.Milliseconds())
	}

	args := BuildBrowserArgs(opts, budgetMs, targetURL)

	cmd := exec.CommandContext(execCtx, binPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	res.Duration = time.Since(start)

	if execCtx.Err() == context.DeadlineExceeded {
		res.Inconclusive = true
		res.Reason = fmt.Sprintf("headless browser execution timed out after %v", timeout)
		return res, ErrBrowserTimeout
	}

	if runErr != nil && stdout.Len() == 0 {
		res.Inconclusive = true
		res.Reason = fmt.Sprintf("headless browser exited with error: %v (stderr: %s)", runErr, strings.TrimSpace(stderr.String()))
		return res, nil
	}

	renderedHTML := stdout.String()
	res.RenderedHTML = renderedHTML

	// 4. Extract dynamic endpoints from rendered HTML DOM
	parsedBase, err := url.Parse(targetURL)
	if err != nil {
		return res, fmt.Errorf("invalid target URL: %w", err)
	}

	endpoints := ExtractDynamicEndpoints(renderedHTML, parsedBase, scope)
	res.Endpoints = endpoints

	return res, nil
}

// BuildBrowserArgs constructs CLI arguments for Chromium headless execution.
// Sandbox protections remain active by default and are only disabled if explicitly opted-in via DisableSandbox.
func BuildBrowserArgs(opts BrowserDiscoveryOptions, budgetMs int, targetURL string) []string {
	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-first-run",
		"--no-default-browser-check",
		fmt.Sprintf("--virtual-time-budget=%d", budgetMs),
		"--dump-dom",
	}
	if opts.DisableSandbox {
		args = append(args, "--no-sandbox")
	}
	args = append(args, targetURL)
	return args
}

// FindBrowserBinary resolves the path to an installed Chromium-compatible browser.
func FindBrowserBinary(customPath string) (string, error) {
	if customPath != "" {
		if _, err := os.Stat(customPath); err == nil {
			return customPath, nil
		}
		if p, err := exec.LookPath(customPath); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("configured browser binary not found: %s", customPath)
	}

	// 1. Check PATH
	candidates := []string{"msedge", "chrome", "chromium", "google-chrome", "chromium-browser"}
	for _, name := range candidates {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}

	// 2. Check standard OS filesystem locations
	switch runtime.GOOS {
	case "windows":
		winPaths := []string{
			`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		}
		for _, p := range winPaths {
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	case "darwin":
		macPaths := []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
		for _, p := range macPaths {
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	case "linux":
		linuxPaths := []string{
			"/usr/bin/google-chrome",
			"/usr/bin/google-chrome-stable",
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/usr/bin/microsoft-edge-stable",
			"/snap/bin/chromium",
		}
		for _, p := range linuxPaths {
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}

	return "", ErrNoBrowserFound
}

// Regex patterns for dynamic API calls in inline scripts
var (
	fetchRegex  = regexp.MustCompile(`(?i)fetch\s*\(\s*['"]([^'"]+)['"]`)
	axiosRegex  = regexp.MustCompile(`(?i)axios\.(?:get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]`)
	ajaxRegex   = regexp.MustCompile(`(?i)\$\.(?:get|post|ajax)\s*\(\s*['"]([^'"]+)['"]`)
	apiURIRegex = regexp.MustCompile(`(?i)['"](/api/[a-zA-Z0-9_\-./]+)['"]`)
)

// ExtractDynamicEndpoints parses DOM HTML and extracts links, forms, scripts, and runtime API calls.
func ExtractDynamicEndpoints(htmlContent string, baseURL *url.URL, scope *Scope) []DynamicEndpoint {
	var endpoints []DynamicEndpoint
	seen := make(map[string]struct{})

	addEndpoint := func(rawURL string, assetType AssetType, inferred bool) {
		if rawURL == "" || strings.HasPrefix(rawURL, "javascript:") || strings.HasPrefix(rawURL, "mailto:") || strings.HasPrefix(rawURL, "#") {
			return
		}

		resolved, err := resolveURL(baseURL, rawURL)
		if err != nil {
			return
		}

		if _, exists := seen[resolved]; exists {
			return
		}
		seen[resolved] = struct{}{}

		inScope := true
		if scope != nil {
			inScope = scope.IsAllowed(resolved)
		}

		endpoints = append(endpoints, DynamicEndpoint{
			URL:        resolved,
			Type:       assetType,
			InScope:    inScope,
			Provenance: ProvenanceBrowser,
			Inferred:   inferred,
		})
	}

	// 1. Parse HTML DOM tree
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err == nil {
		var walk func(*html.Node)
		walk = func(n *html.Node) {
			if n.Type == html.ElementNode {
				switch strings.ToLower(n.Data) {
				case "a":
					for _, attr := range n.Attr {
						if strings.EqualFold(attr.Key, "href") {
							addEndpoint(attr.Val, AssetUnknown, false)
						}
					}
				case "script":
					for _, attr := range n.Attr {
						if strings.EqualFold(attr.Key, "src") {
							addEndpoint(attr.Val, AssetJavaScript, false)
						}
					}
				case "link":
					var href, rel string
					for _, attr := range n.Attr {
						if strings.EqualFold(attr.Key, "href") {
							href = attr.Val
						} else if strings.EqualFold(attr.Key, "rel") {
							rel = strings.ToLower(attr.Val)
						}
					}
					if href != "" {
						if rel == "stylesheet" {
							addEndpoint(href, AssetStylesheet, false)
						} else if rel == "manifest" {
							addEndpoint(href, AssetManifest, false)
						} else {
							addEndpoint(href, AssetUnknown, false)
						}
					}
				case "form":
					for _, attr := range n.Attr {
						if strings.EqualFold(attr.Key, "action") {
							addEndpoint(attr.Val, AssetUnknown, false)
						}
					}
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
		}
		walk(doc)
	}

	// 2. Scan inline scripts and strings for runtime API invocations (Inferred heuristic pattern matches)
	for _, m := range fetchRegex.FindAllStringSubmatch(htmlContent, -1) {
		if len(m) > 1 {
			addEndpoint(m[1], AssetUnknown, true)
		}
	}
	for _, m := range axiosRegex.FindAllStringSubmatch(htmlContent, -1) {
		if len(m) > 1 {
			addEndpoint(m[1], AssetUnknown, true)
		}
	}
	for _, m := range ajaxRegex.FindAllStringSubmatch(htmlContent, -1) {
		if len(m) > 1 {
			addEndpoint(m[1], AssetUnknown, true)
		}
	}
	for _, m := range apiURIRegex.FindAllStringSubmatch(htmlContent, -1) {
		if len(m) > 1 {
			addEndpoint(m[1], AssetUnknown, true)
		}
	}

	return endpoints
}
