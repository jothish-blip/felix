package crawler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// Config defines crawler runtime options.
type Config struct {
	Concurrency int
	Timeout     time.Duration
	UserAgent   string
}

// DefaultConfig provides sensible defaults for web auditing.
func DefaultConfig() Config {
	return Config{
		Concurrency: 10,
		Timeout:     10 * time.Second,
		UserAgent:   "Felix/1.0 (Security Auditing CLI; +https://github.com/felix-sec)",
	}
}

// Result holds the extracted script URLs for a given target.
type Result struct {
	Target  string
	Scripts []string
	Err     error
}

// Crawler manages concurrent web asset discovery.
type Crawler struct {
	config Config
	client *http.Client
}

// New creates a new Crawler instance with the specified configuration.
func New(cfg Config) *Crawler {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = DefaultConfig().UserAgent
	}

	return &Crawler{
		config: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				return nil
			},
		},
	}
}

// ExtractScripts fetches a single HTML page and extracts all resolved <script src="..."> URLs.
func (c *Crawler) ExtractScripts(ctx context.Context, rawURL string) ([]string, error) {
	parsedBase, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", c.config.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return parseScriptTags(resp.Body, parsedBase)
}

// parseScriptTags scans an HTML stream and returns unique, absolute script URLs.
func parseScriptTags(r io.Reader, baseURL *url.URL) ([]string, error) {
	tokenizer := html.NewTokenizer(r)
	seen := make(map[string]struct{})
	var scripts []string

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			err := tokenizer.Err()
			if err == io.EOF {
				return scripts, nil
			}
			return scripts, err

		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			if strings.EqualFold(token.Data, "script") {
				for _, attr := range token.Attr {
					if strings.EqualFold(attr.Key, "src") {
						src := strings.TrimSpace(attr.Val)
						if src == "" {
							continue
						}

						resolved, err := resolveURL(baseURL, src)
						if err != nil {
							continue
						}

						if _, exists := seen[resolved]; !exists {
							seen[resolved] = struct{}{}
							scripts = append(scripts, resolved)
						}
					}
				}
			}
		}
	}
}

// resolveURL resolves relative, protocol-relative, or absolute URLs against the base URL.
func resolveURL(base *url.URL, ref string) (string, error) {
	parsedRef, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(parsedRef).String(), nil
}

// CrawlConcurrently crawls multiple target URLs concurrently using a bounded worker pool.
func (c *Crawler) CrawlConcurrently(ctx context.Context, targets []string) <-chan Result {
	results := make(chan Result, len(targets))
	sem := make(chan struct{}, c.config.Concurrency)
	var wg sync.WaitGroup

	go func() {
		defer close(results)

		for _, target := range targets {
			wg.Add(1)
			sem <- struct{}{}

			go func(t string) {
				defer wg.Done()
				defer func() { <-sem }()

				scripts, err := c.ExtractScripts(ctx, t)
				results <- Result{
					Target:  t,
					Scripts: scripts,
					Err:     err,
				}
			}(target)
		}

		wg.Wait()
	}()

	return results
}
