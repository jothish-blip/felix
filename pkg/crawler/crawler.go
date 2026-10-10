package crawler

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// Result holds the extracted assets and metadata for a given target.
type Result struct {
	Target  string               `json:"target"`
	Scripts []string             `json:"scripts"` // Discovered script URLs (for backward compatibility)
	Assets  []Asset              `json:"assets"`  // Full inventory of discovered and processed assets
	HTML             []byte                  `json:"-"`       // Raw HTML body of target page
	Header           http.Header             `json:"-"`       // HTTP response headers from target page
	TLS              *tls.ConnectionState    `json:"-"`       // TLS handshake state if HTTPS
	BrowserDiscovery *BrowserDiscoveryResult `json:"browser_discovery,omitempty"`
	Err              error                   `json:"error,omitempty"`
}

// DiscoveredAsset stores a URL and its initial detected type from HTML tags.
type DiscoveredAsset struct {
	URL  string
	Type AssetType
}

// Crawler manages concurrent web asset discovery and ingestion.
type Crawler struct {
	config Config
	client *http.Client
}

// New creates a new Crawler instance with the specified configuration.
func New(cfg Config) *Crawler {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxAssetSize <= 0 {
		cfg.MaxAssetSize = DefaultMaxAssetSize
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = DefaultUserAgent
	}
	if cfg.ScopeMode == "" {
		cfg.ScopeMode = ScopeSameOrigin
	}

	client := cfg.Client
	if client == nil {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		if cfg.InsecureSkipVerify {
			tlsConfig.InsecureSkipVerify = true
		}

		transport := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   cfg.Timeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   20,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
			TLSClientConfig:       tlsConfig,
		}

		client = &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				return nil
			},
		}
	}

	return &Crawler{
		config: cfg,
		client: client,
	}
}

// ExtractScripts fetches a single HTML page and extracts all resolved <script src="..."> URLs.
// Preserved for backward compatibility.
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

	scope, _ := NewScope(rawURL, c.config.ScopeMode, c.config.AllowedHosts...)
	targetClient := c.scopedClientForTarget(scope)

	resp, err := targetClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return parseScriptTags(resp.Body, parsedBase)
}

// scopedClientForTarget returns an HTTP client that validates every redirect against
// the active target's approved scope and exclusions before the redirected request is sent.
func (c *Crawler) scopedClientForTarget(scope *Scope) *http.Client {
	base := c.client
	origCheck := base.CheckRedirect

	return &http.Client{
		Transport: base.Transport,
		Timeout:   base.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if origCheck != nil {
				if err := origCheck(req, via); err != nil {
					return err
				}
			}
			nextURL := req.URL.String()
			if c.config.IsExcluded != nil && c.config.IsExcluded(nextURL) {
				return fmt.Errorf("redirect to %s blocked: matches exclusion rule", nextURL)
			}
			if c.config.IsAllowed != nil {
				if !c.config.IsAllowed(nextURL) {
					return fmt.Errorf("redirect to %s blocked: out of approved scope", nextURL)
				}
			} else if scope != nil && !scope.IsAllowed(nextURL) {
				return fmt.Errorf("redirect to %s blocked: out of crawler scope", nextURL)
			}
			if len(via) > 0 {
				lastHost := strings.ToLower(via[len(via)-1].URL.Hostname())
				nextHost := strings.ToLower(req.URL.Hostname())
				if (c.config.ScopeMode == ScopeSameOrigin || c.config.ScopeMode == "") && lastHost != "" && nextHost != "" && lastHost != nextHost {
					return fmt.Errorf("cross-host redirect from %s to %s blocked in same-origin mode", lastHost, nextHost)
				}
			}
			return nil
		},
	}
}

// Crawl executes the full Engine 1 pipeline against a single target URL:
// Scope validation -> HTTP request -> HTML parsing -> Asset discovery -> URL normalization ->
// Deduplication -> Worker pool -> Asset download -> Response validation -> Size limits ->
// Asset classification -> Source map detection -> Asset inventory.
func (c *Crawler) Crawl(ctx context.Context, rawTarget string) Result {
	res := Result{
		Target: rawTarget,
	}

	scope, err := NewScope(rawTarget, c.config.ScopeMode, c.config.AllowedHosts...)
	if err != nil {
		res.Err = fmt.Errorf("scope initialization failed: %w", err)
		return res
	}

	targetClient := c.scopedClientForTarget(scope)

	parsedBase, err := url.Parse(rawTarget)
	if err != nil {
		res.Err = fmt.Errorf("invalid target URL: %w", err)
		return res
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawTarget, nil)
	if err != nil {
		res.Err = fmt.Errorf("failed to create request: %w", err)
		return res
	}
	req.Header.Set("User-Agent", c.config.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := targetClient.Do(req)
	if err != nil {
		res.Err = fmt.Errorf("request failed: %w", err)
		return res
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		res.Err = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		return res
	}

	// Size limit on initial HTML page
	if resp.ContentLength > c.config.MaxAssetSize {
		res.Err = ErrAssetTooLarge
		return res
	}

	lr := io.LimitReader(resp.Body, c.config.MaxAssetSize+1)
	bodyBytes, err := io.ReadAll(lr)
	if err != nil {
		res.Err = fmt.Errorf("failed to read response body: %w", err)
		return res
	}
	if int64(len(bodyBytes)) > c.config.MaxAssetSize {
		res.Err = ErrAssetTooLarge
		return res
	}

	res.HTML = bodyBytes
	res.Header = resp.Header
	res.TLS = resp.TLS

	// Parse HTML for assets
	discovered, scriptURLs, err := parseHTMLAssets(bytes.NewReader(bodyBytes), parsedBase)
	if err != nil && len(discovered) == 0 {
		res.Err = fmt.Errorf("HTML parsing failed: %w", err)
		return res
	}

	res.Scripts = scriptURLs

	// Concurrently download assets with worker pool
	var (
		assetsMu sync.Mutex
		assets   []Asset
		seen     = make(map[string]struct{})
		wg       sync.WaitGroup
		sem      = make(chan struct{}, c.config.Concurrency)
	)

	// Filter and mark seen
	var toDownload []DiscoveredAsset
	for _, da := range discovered {
		if c.config.MaxAssets > 0 && len(toDownload) >= c.config.MaxAssets {
			break
		}
		if _, exists := seen[da.URL]; exists {
			continue
		}
		seen[da.URL] = struct{}{}
		toDownload = append(toDownload, da)
	}

	// Phase 1: Download discovered assets
	for _, da := range toDownload {
		inScope := scope.IsAllowed(da.URL)
		if !inScope {
			assetsMu.Lock()
			assets = append(assets, Asset{
				URL:        da.URL,
				Type:       da.Type,
				InScope:    false,
				Provenance: ProvenanceStatic,
			})
			assetsMu.Unlock()
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(item DiscoveredAsset) {
			defer wg.Done()
			defer func() { <-sem }()

			downloaded := c.downloadAsset(ctx, targetClient, item.URL, item.Type)
			assetsMu.Lock()
			assets = append(assets, downloaded)
			assetsMu.Unlock()
		}(da)
	}

	wg.Wait()

	// Phase 2: Source map discovery from downloaded JavaScript assets
	var sourceMapJobs []string
	if c.config.MaxAssets <= 0 || len(assets) < c.config.MaxAssets {
		for _, a := range assets {
			if (a.Type == AssetJavaScript || strings.HasSuffix(a.URL, ".js")) && len(a.Content) > 0 {
				smRef := ExtractSourceMapURL(a.Content)
				if smRef != "" {
					parsedAssetURL, err := url.Parse(a.URL)
					if err == nil {
						smURL, err := resolveURL(parsedAssetURL, smRef)
						if err == nil {
							if _, exists := seen[smURL]; !exists {
								seen[smURL] = struct{}{}
								sourceMapJobs = append(sourceMapJobs, smURL)
								if c.config.MaxAssets > 0 && len(assets)+len(sourceMapJobs) >= c.config.MaxAssets {
									break
								}
							}
						}
					}
				}
			}
		}
	}

	// Download discovered source maps
	for _, smURL := range sourceMapJobs {
		inScope := scope.IsAllowed(smURL)
		if !inScope {
			assetsMu.Lock()
			assets = append(assets, Asset{
				URL:         smURL,
				Type:        AssetSourceMap,
				IsSourceMap: true,
				InScope:     false,
				Provenance:  ProvenanceStatic,
			})
			assetsMu.Unlock()
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(targetURL string) {
			defer wg.Done()
			defer func() { <-sem }()

			smAsset := c.downloadAsset(ctx, targetClient, targetURL, AssetSourceMap)
			smAsset.Type = AssetSourceMap
			smAsset.IsSourceMap = true
			smAsset.Provenance = ProvenanceStatic
			assetsMu.Lock()
			assets = append(assets, smAsset)
			assetsMu.Unlock()
		}(smURL)
	}

	wg.Wait()

	// Phase 3: Dynamic Browser Discovery (if enabled)
	if c.config.BrowserDiscovery.Enabled {
		driver := c.config.BrowserDiscovery.Driver
		if driver == nil {
			driver = NewHeadlessBrowserDriver()
		}

		browserTimeout := c.config.BrowserDiscovery.Timeout
		if browserTimeout <= 0 {
			browserTimeout = 10 * time.Second
		}
		browserCtx, browserCancel := context.WithTimeout(ctx, browserTimeout)
		defer browserCancel()

		browserRes, bErr := driver.Discover(browserCtx, rawTarget, c.config.BrowserDiscovery, scope)
		if browserRes != nil {
			res.BrowserDiscovery = browserRes
			if bErr != nil {
				res.BrowserDiscovery.Inconclusive = true
				if res.BrowserDiscovery.Reason == "" {
					res.BrowserDiscovery.Reason = bErr.Error()
				}
			}

			var dynamicJobs []DynamicEndpoint
			for _, ep := range browserRes.Endpoints {
				if _, exists := seen[ep.URL]; !exists {
					seen[ep.URL] = struct{}{}
					dynamicJobs = append(dynamicJobs, ep)
					if ep.Type == AssetJavaScript {
						res.Scripts = append(res.Scripts, ep.URL)
					}
				}
			}

			for _, ep := range dynamicJobs {
				if c.config.MaxAssets > 0 && len(assets) >= c.config.MaxAssets {
					break
				}
				if !ep.InScope {
					assets = append(assets, Asset{
						URL:        ep.URL,
						Type:       ep.Type,
						InScope:    false,
						Provenance: ProvenanceBrowser,
						Inferred:   ep.Inferred,
					})
					continue
				}

				if ep.Type == AssetJavaScript || ep.Type == AssetStylesheet || ep.Type == AssetManifest || ep.Type == AssetSourceMap {
					down := c.downloadAsset(ctx, targetClient, ep.URL, ep.Type)
					down.Provenance = ProvenanceBrowser
					down.Inferred = ep.Inferred
					assets = append(assets, down)
				} else {
					assets = append(assets, Asset{
						URL:        ep.URL,
						Type:       ep.Type,
						InScope:    true,
						Provenance: ProvenanceBrowser,
						Inferred:   ep.Inferred,
					})
				}
			}
		} else if bErr != nil {
			res.BrowserDiscovery = &BrowserDiscoveryResult{
				Inconclusive: true,
				Reason:       bErr.Error(),
			}
		}
	}

	if c.config.MaxAssets > 0 {
		if len(assets) > c.config.MaxAssets {
			assets = assets[:c.config.MaxAssets]
		}
		if len(res.Scripts) > c.config.MaxAssets {
			res.Scripts = res.Scripts[:c.config.MaxAssets]
		}
	}

	res.Assets = assets
	return res
}

// downloadAsset fetches an individual asset subject to size limits and error handling.
func (c *Crawler) downloadAsset(ctx context.Context, client *http.Client, assetURL string, defaultType AssetType) Asset {
	if client == nil {
		client = c.client
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
	if err != nil {
		return Asset{
			URL:     assetURL,
			Type:    defaultType,
			InScope: true,
			Error:   err,
		}
	}
	req.Header.Set("User-Agent", c.config.UserAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return Asset{
			URL:     assetURL,
			Type:    defaultType,
			InScope: true,
			Error:   err,
		}
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	classifiedType := ClassifyAsset(assetURL, contentType)
	if classifiedType == AssetUnknown && defaultType != AssetUnknown {
		classifiedType = defaultType
	}

	asset := Asset{
		URL:         assetURL,
		Type:        classifiedType,
		StatusCode:  resp.StatusCode,
		ContentType: contentType,
		IsSourceMap: classifiedType == AssetSourceMap,
		InScope:     true,
		Provenance:  ProvenanceStatic,
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		asset.Error = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		return asset
	}

	// Size Limit Validation
	if resp.ContentLength > c.config.MaxAssetSize {
		asset.Error = ErrAssetTooLarge
		return asset
	}

	limit := c.config.MaxAssetSize
	lr := io.LimitReader(resp.Body, limit+1)
	content, err := io.ReadAll(lr)
	if err != nil {
		asset.Error = err
		return asset
	}

	if int64(len(content)) > limit {
		asset.Error = ErrAssetTooLarge
		return asset
	}

	asset.Content = content
	asset.Size = int64(len(content))
	return asset
}

// parseHTMLAssets extracts discovered script, stylesheet, and manifest assets.
func parseHTMLAssets(r io.Reader, baseURL *url.URL) ([]DiscoveredAsset, []string, error) {
	tokenizer := html.NewTokenizer(r)
	seen := make(map[string]struct{})
	seenScripts := make(map[string]struct{})

	var assets []DiscoveredAsset
	var scripts []string

	currentBase := baseURL

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			err := tokenizer.Err()
			if err == io.EOF {
				return assets, scripts, nil
			}
			return assets, scripts, err

		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()

			// Check for <base href="...">
			if strings.EqualFold(token.Data, "base") {
				for _, attr := range token.Attr {
					if strings.EqualFold(attr.Key, "href") {
						baseHref := strings.TrimSpace(attr.Val)
						if baseHref != "" {
							if newBase, err := resolveURL(currentBase, baseHref); err == nil {
								if parsed, err := url.Parse(newBase); err == nil {
									currentBase = parsed
								}
							}
						}
					}
				}
				continue
			}

			// 1. <script src="...">
			if strings.EqualFold(token.Data, "script") {
				for _, attr := range token.Attr {
					if strings.EqualFold(attr.Key, "src") {
						src := strings.TrimSpace(attr.Val)
						if src == "" {
							continue
						}

						lowerSrc := strings.ToLower(src)
						if strings.HasPrefix(lowerSrc, "javascript:") ||
							strings.HasPrefix(lowerSrc, "data:") ||
							strings.HasPrefix(lowerSrc, "mailto:") ||
							strings.HasPrefix(lowerSrc, "#") {
							continue
						}

						resolved, err := resolveURL(currentBase, src)
						if err != nil {
							continue
						}

						parsedRes, err := url.Parse(resolved)
						if err != nil || (parsedRes.Scheme != "" && !strings.EqualFold(parsedRes.Scheme, "http") && !strings.EqualFold(parsedRes.Scheme, "https")) {
							continue
						}

						if _, exists := seenScripts[resolved]; !exists {
							seenScripts[resolved] = struct{}{}
							scripts = append(scripts, resolved)
						}

						if _, exists := seen[resolved]; !exists {
							seen[resolved] = struct{}{}
							assets = append(assets, DiscoveredAsset{
								URL:  resolved,
								Type: AssetJavaScript,
							})
						}
					}
				}
				continue
			}

			// 2. <link rel="..." href="...">
			if strings.EqualFold(token.Data, "link") {
				var relVal, hrefVal, asVal string
				for _, attr := range token.Attr {
					switch strings.ToLower(attr.Key) {
					case "rel":
						relVal = strings.TrimSpace(attr.Val)
					case "href":
						hrefVal = strings.TrimSpace(attr.Val)
					case "as":
						asVal = strings.TrimSpace(attr.Val)
					}
				}

				if hrefVal == "" {
					continue
				}

				lowerHref := strings.ToLower(hrefVal)
				if strings.HasPrefix(lowerHref, "javascript:") ||
					strings.HasPrefix(lowerHref, "data:") ||
					strings.HasPrefix(lowerHref, "mailto:") ||
					strings.HasPrefix(lowerHref, "#") {
					continue
				}

				resolved, err := resolveURL(currentBase, hrefVal)
				if err != nil {
					continue
				}

				parsedRes, err := url.Parse(resolved)
				if err != nil || (parsedRes.Scheme != "" && !strings.EqualFold(parsedRes.Scheme, "http") && !strings.EqualFold(parsedRes.Scheme, "https")) {
					continue
				}

				var assetType AssetType
				lowerRel := strings.ToLower(relVal)
				lowerAs := strings.ToLower(asVal)

				switch {
				case strings.Contains(lowerRel, "stylesheet"):
					assetType = AssetStylesheet
				case strings.Contains(lowerRel, "manifest"):
					assetType = AssetManifest
				case strings.Contains(lowerRel, "preload") || strings.Contains(lowerRel, "modulepreload"):
					if lowerAs == "script" {
						assetType = AssetJavaScript
					} else if lowerAs == "style" {
						assetType = AssetStylesheet
					} else {
						assetType = ClassifyAsset(resolved, "")
					}
				default:
					assetType = ClassifyAsset(resolved, "")
				}

				if assetType != AssetUnknown {
					if _, exists := seen[resolved]; !exists {
						seen[resolved] = struct{}{}
						assets = append(assets, DiscoveredAsset{
							URL:  resolved,
							Type: assetType,
						})
						if assetType == AssetJavaScript {
							if _, exists := seenScripts[resolved]; !exists {
								seenScripts[resolved] = struct{}{}
								scripts = append(scripts, resolved)
							}
						}
					}
				}
			}
		}
	}
}

// parseScriptTags scans an HTML stream and returns unique, absolute script URLs.
func parseScriptTags(r io.Reader, baseURL *url.URL) ([]string, error) {
	tokenizer := html.NewTokenizer(r)
	seen := make(map[string]struct{})
	var scripts []string

	currentBase := baseURL

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

			if strings.EqualFold(token.Data, "base") {
				for _, attr := range token.Attr {
					if strings.EqualFold(attr.Key, "href") {
						baseHref := strings.TrimSpace(attr.Val)
						if baseHref != "" {
							if newBase, err := resolveURL(currentBase, baseHref); err == nil {
								if parsed, err := url.Parse(newBase); err == nil {
									currentBase = parsed
								}
							}
						}
					}
				}
				continue
			}

			if strings.EqualFold(token.Data, "script") {
				for _, attr := range token.Attr {
					if strings.EqualFold(attr.Key, "src") {
						src := strings.TrimSpace(attr.Val)
						if src == "" {
							continue
						}

						lowerSrc := strings.ToLower(src)
						if strings.HasPrefix(lowerSrc, "javascript:") ||
							strings.HasPrefix(lowerSrc, "data:") ||
							strings.HasPrefix(lowerSrc, "mailto:") ||
							strings.HasPrefix(lowerSrc, "#") {
							continue
						}

						resolved, err := resolveURL(currentBase, src)
						if err != nil {
							continue
						}

						parsedRes, err := url.Parse(resolved)
						if err != nil || (parsedRes.Scheme != "" && !strings.EqualFold(parsedRes.Scheme, "http") && !strings.EqualFold(parsedRes.Scheme, "https")) {
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

				res := c.Crawl(ctx, t)
				results <- res
			}(target)
		}

		wg.Wait()
	}()

	return results
}
