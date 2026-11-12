package crawler

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/html"
)

var defaultDestructivePatterns = []string{
	"logout", "signout", "sign-out", "log-out",
	"delete", "destroy", "deactivate", "cancel",
	"pay", "payment", "billing", "purchase", "checkout", "terminate", "unregister",
	"purge", "revoke", "remove", "restart", "reboot",
	"wipe", "truncate", "erase", "shutdown", "nuke",
	"password", "passwd",
}

// ActiveCrawlOptions configures the recursive crawl and active discovery pipeline.
type ActiveCrawlOptions struct {
	TargetURL           string
	MaxDepth            int
	MaxPages            int
	MaxRequests         int
	Timeout             time.Duration
	MaxAssetSize        int64
	Concurrency         int
	ScopeMode           ScopeMode
	AllowedHosts        []string
	AllowLoopback       bool
	AllowPrivateIPs     bool
	IsAllowed           func(string) bool
	IsExcluded          func(string) bool
	DestructivePatterns []string
	BundleAnalysis      BundleAnalysisOptions
	Progress            func(string)
}

// DefaultActiveCrawlOptions returns secure, bounded defaults.
func DefaultActiveCrawlOptions(targetURL string) ActiveCrawlOptions {
	return ActiveCrawlOptions{
		TargetURL:           targetURL,
		MaxDepth:            3,
		MaxPages:            25,
		MaxRequests:         50,
		Timeout:             10 * time.Second,
		MaxAssetSize:        10 * 1024 * 1024,
		Concurrency:         5,
		ScopeMode:           ScopeSameOrigin,
		DestructivePatterns: defaultDestructivePatterns,
		BundleAnalysis:      DefaultBundleAnalysisOptions(),
	}
}

// IsDestructiveURL checks whether a URL path or query parameters match destructive action patterns.
func IsDestructiveURL(rawURL string, customPatterns []string) (bool, string) {
	patterns := defaultDestructivePatterns
	if len(customPatterns) > 0 {
		patterns = customPatterns
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		lower := strings.ToLower(rawURL)
		for _, p := range patterns {
			if strings.Contains(lower, p) {
				return true, fmt.Sprintf("pattern %q in raw URL", p)
			}
		}
		return false, ""
	}

	// Check path segments
	cleanPath := strings.ToLower(parsed.Path)
	pathSegments := strings.Split(cleanPath, "/")
	for _, seg := range pathSegments {
		segClean := strings.Trim(seg, "._-")
		for _, p := range patterns {
			if segClean == p || strings.HasPrefix(segClean, p+"_") || strings.HasPrefix(segClean, p+"-") || strings.HasSuffix(segClean, "_"+p) || strings.HasSuffix(segClean, "-"+p) {
				return true, fmt.Sprintf("path segment %q matches destructive pattern %q", seg, p)
			}
		}
	}

	// Check query parameter names and values
	for k, vals := range parsed.Query() {
		kLower := strings.ToLower(k)
		for _, p := range patterns {
			if kLower == p || strings.Contains(kLower, p) {
				return true, fmt.Sprintf("query parameter %q matches destructive pattern %q", k, p)
			}
		}
		for _, v := range vals {
			vLower := strings.ToLower(v)
			for _, p := range patterns {
				if vLower == p {
					return true, fmt.Sprintf("query value %q matches destructive pattern %q", v, p)
				}
			}
		}
	}

	return false, ""
}

// ExtractHTMLLinksAndForms parses HTML content to identify navigation links, forms, scripts, and static resources.
func ExtractHTMLLinksAndForms(r io.Reader, baseURL *url.URL) (links []string, forms []ExtractedForm, staticAssets []DiscoveredAsset, err error) {
	tokenizer := html.NewTokenizer(r)
	seenLinks := make(map[string]bool)
	seenScripts := make(map[string]bool)
	seenStatic := make(map[string]bool)

	currentBase := baseURL

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			err := tokenizer.Err()
			if err == io.EOF {
				return links, forms, staticAssets, nil
			}
			return links, forms, staticAssets, err

		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			tagName := strings.ToLower(token.Data)

			switch tagName {
			case "base":
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

			case "a":
				for _, attr := range token.Attr {
					if strings.EqualFold(attr.Key, "href") {
						href := strings.TrimSpace(attr.Val)
						if href == "" || strings.HasPrefix(href, "#") {
							continue
						}
						lowerHref := strings.ToLower(href)
						if strings.HasPrefix(lowerHref, "javascript:") ||
							strings.HasPrefix(lowerHref, "mailto:") ||
							strings.HasPrefix(lowerHref, "tel:") ||
							strings.HasPrefix(lowerHref, "data:") {
							continue
						}
						resolved, err := resolveURL(currentBase, href)
						if err == nil && resolved != "" {
							norm, err := NormalizeCrawlURL(resolved)
							if err == nil && !seenLinks[norm] {
								seenLinks[norm] = true
								links = append(links, norm)
							}
						}
					}
				}

			case "form":
				var form ExtractedForm
				form.Method = "GET" // Default HTML form method
				for _, attr := range token.Attr {
					switch strings.ToLower(attr.Key) {
					case "action":
						form.Action = strings.TrimSpace(attr.Val)
					case "method":
						m := strings.ToUpper(strings.TrimSpace(attr.Val))
						if m != "" {
							form.Method = m
						}
					}
				}

				if form.Action == "" {
					form.ResolvedURL = currentBase.String()
				} else {
					if res, err := resolveURL(currentBase, form.Action); err == nil {
						form.ResolvedURL = res
					} else {
						form.ResolvedURL = form.Action
					}
				}

				// Collect form inputs until </form>
				for {
					subTT := tokenizer.Next()
					if subTT == html.ErrorToken {
						break
					}
					if subTT == html.EndTagToken {
						subTok := tokenizer.Token()
						if strings.EqualFold(subTok.Data, "form") {
							break
						}
					}
					if subTT == html.StartTagToken || subTT == html.SelfClosingTagToken {
						subTok := tokenizer.Token()
						subTag := strings.ToLower(subTok.Data)
						if subTag == "input" || subTag == "select" || subTag == "textarea" {
							var field FormField
							field.Type = "text"
							if subTag == "textarea" {
								field.Type = "textarea"
							} else if subTag == "select" {
								field.Type = "select"
							}
							for _, a := range subTok.Attr {
								switch strings.ToLower(a.Key) {
								case "name":
									field.Name = strings.TrimSpace(a.Val)
								case "type":
									field.Type = strings.ToLower(strings.TrimSpace(a.Val))
								case "value":
									field.Value = a.Val
								case "required":
									field.Required = true
								}
							}
							if field.Name != "" {
								form.Fields = append(form.Fields, field)
							}
						}
					}
				}
				forms = append(forms, form)

			case "script":
				for _, attr := range token.Attr {
					if strings.EqualFold(attr.Key, "src") {
						src := strings.TrimSpace(attr.Val)
						if src == "" {
							continue
						}
						lowerSrc := strings.ToLower(src)
						if strings.HasPrefix(lowerSrc, "javascript:") || strings.HasPrefix(lowerSrc, "data:") {
							continue
						}
						resolved, err := resolveURL(currentBase, src)
						if err == nil && !seenScripts[resolved] {
							seenScripts[resolved] = true
							staticAssets = append(staticAssets, DiscoveredAsset{
								URL:  resolved,
								Type: AssetJavaScript,
							})
						}
					}
				}

			case "link":
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
				if hrefVal != "" {
					resolved, err := resolveURL(currentBase, hrefVal)
					if err == nil && !seenStatic[resolved] {
						seenStatic[resolved] = true
						aType := ClassifyAsset(resolved, "")
						if strings.Contains(strings.ToLower(relVal), "stylesheet") || strings.ToLower(asVal) == "style" {
							aType = AssetStylesheet
						} else if strings.ToLower(asVal) == "script" {
							aType = AssetJavaScript
						}
						if aType != AssetUnknown {
							staticAssets = append(staticAssets, DiscoveredAsset{
								URL:  resolved,
								Type: aType,
							})
						}
					}
				}
			}
		}
	}
}

type crawlQueueItem struct {
	URL      string
	Depth    int
	Referrer string
}

// ActiveCrawler coordinates recursive discovery and asset inventory under a specified identity.
type ActiveCrawler struct {
	opts   ActiveCrawlOptions
	scope  *Scope
	bundle *BundleExtractor
}

// NewActiveCrawler constructs an ActiveCrawler configured with safety limits.
func NewActiveCrawler(opts ActiveCrawlOptions) (*ActiveCrawler, error) {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 3
	}
	if opts.MaxPages <= 0 {
		opts.MaxPages = 25
	}
	if opts.MaxRequests <= 0 {
		opts.MaxRequests = 50
	}
	if opts.MaxAssetSize <= 0 {
		opts.MaxAssetSize = 10 * 1024 * 1024
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 5
	}
	if len(opts.DestructivePatterns) == 0 {
		opts.DestructivePatterns = defaultDestructivePatterns
	}

	scope, err := NewScope(opts.TargetURL, opts.ScopeMode, opts.AllowedHosts...)
	if err != nil {
		return nil, fmt.Errorf("scope initialization failed: %w", err)
	}

	beOpts := opts.BundleAnalysis
	if beOpts.MaxBundleSize <= 0 {
		beOpts.MaxBundleSize = opts.MaxAssetSize
	}
	if beOpts.ScopeURL == "" {
		beOpts.ScopeURL = opts.TargetURL
	}

	return &ActiveCrawler{
		opts:   opts,
		scope:  scope,
		bundle: NewBundleExtractor(beOpts),
	}, nil
}

// CrawlApplication executes recursive discovery under a single identity context.
func (ac *ActiveCrawler) CrawlApplication(ctx context.Context, client *http.Client, identity string) (*ActiveCrawlResult, error) {
	if identity == "" {
		identity = "ANONYMOUS"
	}

	res := &ActiveCrawlResult{
		VisibilityMatrix: NewIdentityVisibilityMatrix(identity),
	}

	parsedTarget, err := url.Parse(ac.opts.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	targetHost := parsedTarget.Hostname()

	normRoot, err := NormalizeCrawlURL(ac.opts.TargetURL)
	if err != nil {
		normRoot = ac.opts.TargetURL
	}

	queue := []crawlQueueItem{
		{URL: normRoot, Depth: 0, Referrer: "SEED"},
	}

	visitedURLs := make(map[string]bool)
	visitedURLs[normRoot] = true

	seenResources := make(map[string]bool)
	analyzedBundles := make(map[string]bool)

	totalRequests := 0
	pagesVisited := 0

	addResource := func(dr DiscoveredResource) {
		key := fmt.Sprintf("%s:%s", dr.HTTPMethod, dr.NormalizedURL)
		if !seenResources[key] {
			seenResources[key] = true
			res.Resources = append(res.Resources, dr)

			// Update Summary
			switch dr.Classification {
			case ClassificationConfirmedEndpoint:
				res.Summary.TotalConfirmedEndpoints++
				if dr.AssetType == "page" || strings.Contains(dr.ContentType, "html") {
					res.Summary.TotalPagesDiscovered++
				}
			case ClassificationEndpointCandidate:
				res.Summary.TotalEndpointCandidates++
			case ClassificationObservedForm:
				res.Summary.TotalFormsAndInputs++
			case ClassificationStaticAsset:
				res.Summary.TotalStaticAssets++
				if dr.AssetType == AssetJavaScript {
					res.Summary.TotalJavaScriptBundles++
				}
			case ClassificationInaccessible:
				res.Summary.TotalInaccessibleResources++
			case ClassificationExcludedDestructive, ClassificationOutOfScope:
				res.Summary.TotalExcludedResources++
			}

			// Record observation in matrix
			routeKey := fmt.Sprintf("%s %s", dr.HTTPMethod, dr.Path)
			obs := IdentityRouteObservation{
				Visible:        dr.AccessibilityState == "REACHABLE",
				StatusCode:     dr.StatusCode,
				StatusText:     dr.AccessibilityState,
				Classification: string(dr.Classification),
			}
			res.VisibilityMatrix.RecordObservation(routeKey, identity, obs)
		}
	}

	addCoverageGap := func(gapType, resource, reason string) {
		res.CoverageGaps = append(res.CoverageGaps, CoverageGapRecord{
			Type:            gapType,
			Resource:        resource,
			Reason:          reason,
			IdentityContext: identity,
		})
	}

	for len(queue) > 0 {
		if ctx.Err() != nil {
			addCoverageGap("LIMIT_REACHED", "crawl_queue", "Context cancelled or timed out")
			break
		}

		if totalRequests >= ac.opts.MaxRequests {
			addCoverageGap("LIMIT_REACHED", "request_budget", fmt.Sprintf("Maximum request budget reached (%d requests)", ac.opts.MaxRequests))
			break
		}

		if pagesVisited >= ac.opts.MaxPages {
			addCoverageGap("LIMIT_REACHED", "page_budget", fmt.Sprintf("Maximum pages budget reached (%d pages)", ac.opts.MaxPages))
			break
		}

		item := queue[0]
		queue = queue[1:]

		// 1. Safety Boundary Check: Destructive pattern
		if isDestructive, reason := IsDestructiveURL(item.URL, ac.opts.DestructivePatterns); isDestructive {
			parsed, _ := url.Parse(item.URL)
			p := "/"
			if parsed != nil && parsed.Path != "" {
				p = parsed.Path
			}
			addResource(DiscoveredResource{
				ID:                 ComputeResourceID(identity, "GET", item.URL),
				URL:                item.URL,
				NormalizedURL:      item.URL,
				Host:               targetHost,
				Path:               p,
				HTTPMethod:         "GET",
				AssetType:          AssetUnknown,
				DiscoveryMethod:    "HTML_CRAWL",
				IdentityContext:    identity,
				DiscoveredAt:       time.Now().UTC(),
				CrawlDepth:         item.Depth,
				InScope:            true,
				Classification:     ClassificationExcludedDestructive,
				Confidence:         "HIGH",
				AccessibilityState: "EXCLUDED",
				ExclusionReason:    fmt.Sprintf("Destructive action prevented: %s", reason),
			})
			addCoverageGap("SAFETY_EXCLUSION", item.URL, fmt.Sprintf("Destructive action excluded: %s", reason))
			continue
		}

		// 2. Scope Boundary Check
		inScope := ac.scope.IsAllowed(item.URL)
		if ac.opts.IsAllowed != nil && !ac.opts.IsAllowed(item.URL) {
			inScope = false
		}
		if ac.opts.IsExcluded != nil && ac.opts.IsExcluded(item.URL) {
			inScope = false
		}

		if !inScope {
			parsed, _ := url.Parse(item.URL)
			p := "/"
			if parsed != nil && parsed.Path != "" {
				p = parsed.Path
			}
			addResource(DiscoveredResource{
				ID:                 ComputeResourceID(identity, "GET", item.URL),
				URL:                item.URL,
				NormalizedURL:      item.URL,
				Host:               targetHost,
				Path:               p,
				HTTPMethod:         "GET",
				DiscoveryMethod:    "HTML_CRAWL",
				IdentityContext:    identity,
				DiscoveredAt:       time.Now().UTC(),
				CrawlDepth:         item.Depth,
				InScope:            false,
				Classification:     ClassificationOutOfScope,
				Confidence:         "HIGH",
				AccessibilityState: "OUT_OF_SCOPE",
				ExclusionReason:    "Outside authorized assessment scope",
			})
			continue
		}

		// 3. Dispatch safe HTTP GET request
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, item.URL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Felix/1.0 (+https://felix-security.org)")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8")

		totalRequests++
		res.Summary.TotalRequestsMade = totalRequests

		if ac.opts.Progress != nil {
			ac.opts.Progress(fmt.Sprintf("[%s] Crawling [depth %d]: %s", identity, item.Depth, item.URL))
		}

		resp, err := client.Do(req)
		if err != nil {
			addCoverageGap("NETWORK_ERROR", item.URL, err.Error())
			continue
		}

		currParsed, _ := url.Parse(item.URL)
		currPath := "/"
		var queryParams []string
		if currParsed != nil {
			if currParsed.Path != "" {
				currPath = currParsed.Path
			}
			for k := range currParsed.Query() {
				queryParams = append(queryParams, k)
			}
			sort.Strings(queryParams)
		}

		contentType := resp.Header.Get("Content-Type")

		// 4. Handle Authentication / Access Control Barriers
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			accState := "UNAUTHORIZED_401"
			if resp.StatusCode == http.StatusForbidden {
				accState = "FORBIDDEN_403"
			}
			addResource(DiscoveredResource{
				ID:                 ComputeResourceID(identity, "GET", item.URL),
				URL:                item.URL,
				NormalizedURL:      item.URL,
				Host:               targetHost,
				Path:               currPath,
				HTTPMethod:         "GET",
				ContentType:        contentType,
				QueryParams:        queryParams,
				AssetType:          AssetUnknown,
				DiscoveryMethod:    "HTML_CRAWL",
				IdentityContext:    identity,
				StatusCode:         resp.StatusCode,
				DiscoveredAt:       time.Now().UTC(),
				CrawlDepth:         item.Depth,
				InScope:            true,
				Classification:     ClassificationInaccessible,
				Confidence:         "HIGH",
				AccessibilityState: accState,
				Evidence:           fmt.Sprintf("HTTP %d received; access control barrier defended", resp.StatusCode),
			})
			addCoverageGap("AUTH_BLOCKED", item.URL, fmt.Sprintf("Access denied with HTTP %d for identity %s", resp.StatusCode, identity))
			continue
		}

		// 5. Handle Redirects
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			resp.Body.Close()
			addResource(DiscoveredResource{
				ID:                 ComputeResourceID(identity, "GET", item.URL),
				URL:                item.URL,
				NormalizedURL:      item.URL,
				Host:               targetHost,
				Path:               currPath,
				HTTPMethod:         "GET",
				ContentType:        contentType,
				QueryParams:        queryParams,
				AssetType:          AssetUnknown,
				DiscoveryMethod:    "HTML_CRAWL",
				IdentityContext:    identity,
				StatusCode:         resp.StatusCode,
				DiscoveredAt:       time.Now().UTC(),
				CrawlDepth:         item.Depth,
				InScope:            true,
				Classification:     ClassificationRedirected,
				Confidence:         "HIGH",
				AccessibilityState: "REDIRECTED",
				Evidence:           fmt.Sprintf("Redirects to %s", loc),
			})

			if loc != "" && item.Depth+1 <= ac.opts.MaxDepth {
				if resLoc, err := resolveURL(currParsed, loc); err == nil {
					normLoc, err := NormalizeCrawlURL(resLoc)
					if err == nil && !visitedURLs[normLoc] {
						visitedURLs[normLoc] = true
						queue = append(queue, crawlQueueItem{
							URL:      normLoc,
							Depth:    item.Depth + 1,
							Referrer: item.URL,
						})
					}
				}
			}
			continue
		}

		// 6. Handle Successful / Observable HTTP Responses (200 OK)
		lr := io.LimitReader(resp.Body, ac.opts.MaxAssetSize+1)
		bodyBytes, readErr := io.ReadAll(lr)
		resp.Body.Close()

		if readErr != nil {
			addCoverageGap("READ_ERROR", item.URL, readErr.Error())
			continue
		}

		if int64(len(bodyBytes)) > ac.opts.MaxAssetSize {
			addCoverageGap("LIMIT_REACHED", item.URL, fmt.Sprintf("Response size (%d bytes) exceeds max limit (%d bytes)", len(bodyBytes), ac.opts.MaxAssetSize))
			continue
		}

		isHTML := strings.Contains(strings.ToLower(contentType), "html") || bytes.Contains(bodyBytes[:min(len(bodyBytes), 512)], []byte("<html"))
		isJSON := strings.Contains(strings.ToLower(contentType), "json")

		assetType := AssetUnknown
		if isHTML {
			assetType = "page"
			pagesVisited++
		} else if isJSON {
			assetType = "api"
		}

		addResource(DiscoveredResource{
			ID:                 ComputeResourceID(identity, "GET", item.URL),
			URL:                item.URL,
			NormalizedURL:      item.URL,
			Host:               targetHost,
			Path:               currPath,
			HTTPMethod:         "GET",
			ContentType:        contentType,
			QueryParams:        queryParams,
			AssetType:          assetType,
			SourcePage:         item.Referrer,
			DiscoveryMethod:    "HTML_CRAWL",
			IdentityContext:    identity,
			StatusCode:         resp.StatusCode,
			DiscoveredAt:       time.Now().UTC(),
			CrawlDepth:         item.Depth,
			InScope:            true,
			Classification:     ClassificationConfirmedEndpoint,
			Confidence:         "HIGH",
			AccessibilityState: "REACHABLE",
		})

		// Track in inventory assets
		res.AssetsForInventory = append(res.AssetsForInventory, Asset{
			URL:         item.URL,
			Type:        assetType,
			Content:     bodyBytes,
			Size:        int64(len(bodyBytes)),
			StatusCode:  resp.StatusCode,
			ContentType: contentType,
			InScope:     true,
			Provenance:  ProvenanceStatic,
		})

		// 7. Parse HTML for child links, forms, and scripts
		if isHTML {
			childLinks, forms, staticAssets, parseErr := ExtractHTMLLinksAndForms(bytes.NewReader(bodyBytes), currParsed)
			if parseErr != nil {
				addCoverageGap("UNPARSED_CONTENT", item.URL, fmt.Sprintf("HTML parser warning: %v", parseErr))
			}

			// Process discovered forms
			for _, form := range forms {
				formMethod := strings.ToUpper(form.Method)
				if formMethod == "" {
					formMethod = "GET"
				}
				formParsed, _ := url.Parse(form.ResolvedURL)
				fPath := "/"
				if formParsed != nil && formParsed.Path != "" {
					fPath = formParsed.Path
				}

				// Check destructive action on form action URL
				if isDestructive, reason := IsDestructiveURL(form.ResolvedURL, ac.opts.DestructivePatterns); isDestructive {
					addResource(DiscoveredResource{
						ID:                 ComputeResourceID(identity, formMethod, form.ResolvedURL),
						URL:                form.ResolvedURL,
						NormalizedURL:      form.ResolvedURL,
						Host:               targetHost,
						Path:               fPath,
						HTTPMethod:         formMethod,
						FormFields:         form.Fields,
						SourcePage:         item.URL,
						DiscoveryMethod:    "HTML_FORM",
						IdentityContext:    identity,
						DiscoveredAt:       time.Now().UTC(),
						CrawlDepth:         item.Depth,
						InScope:            true,
						Classification:     ClassificationExcludedDestructive,
						Confidence:         "HIGH",
						AccessibilityState: "EXCLUDED",
						ExclusionReason:    fmt.Sprintf("Form action destructive: %s", reason),
					})
					addCoverageGap("SAFETY_EXCLUSION", form.ResolvedURL, fmt.Sprintf("Destructive form action excluded: %s", reason))
					continue
				}

				addResource(DiscoveredResource{
					ID:                 ComputeResourceID(identity, formMethod, form.ResolvedURL),
					URL:                form.ResolvedURL,
					NormalizedURL:      form.ResolvedURL,
					Host:               targetHost,
					Path:               fPath,
					HTTPMethod:         formMethod,
					FormFields:         form.Fields,
					SourcePage:         item.URL,
					DiscoveryMethod:    "HTML_FORM",
					IdentityContext:    identity,
					DiscoveredAt:       time.Now().UTC(),
					CrawlDepth:         item.Depth,
					InScope:            ac.scope.IsAllowed(form.ResolvedURL),
					Classification:     ClassificationObservedForm,
					Confidence:         "HIGH",
					AccessibilityState: "REACHABLE",
				})
			}

			// Process discovered child links
			for _, l := range childLinks {
				// Destructive check
				if isDest, reason := IsDestructiveURL(l, ac.opts.DestructivePatterns); isDest {
					p, _ := url.Parse(l)
					pathStr := "/"
					if p != nil && p.Path != "" {
						pathStr = p.Path
					}
					addResource(DiscoveredResource{
						ID:                 ComputeResourceID(identity, "GET", l),
						URL:                l,
						NormalizedURL:      l,
						Host:               targetHost,
						Path:               pathStr,
						HTTPMethod:         "GET",
						SourcePage:         item.URL,
						DiscoveryMethod:    "HTML_CRAWL",
						IdentityContext:    identity,
						DiscoveredAt:       time.Now().UTC(),
						CrawlDepth:         item.Depth + 1,
						InScope:            true,
						Classification:     ClassificationExcludedDestructive,
						Confidence:         "HIGH",
						AccessibilityState: "EXCLUDED",
						ExclusionReason:    fmt.Sprintf("Destructive action excluded: %s", reason),
					})
					continue
				}

				// Scope check
				inScopeLink := ac.scope.IsAllowed(l)
				if ac.opts.IsAllowed != nil && !ac.opts.IsAllowed(l) {
					inScopeLink = false
				}
				if !inScopeLink {
					p, _ := url.Parse(l)
					pathStr := "/"
					if p != nil && p.Path != "" {
						pathStr = p.Path
					}
					addResource(DiscoveredResource{
						ID:                 ComputeResourceID(identity, "GET", l),
						URL:                l,
						NormalizedURL:      l,
						Host:               targetHost,
						Path:               pathStr,
						HTTPMethod:         "GET",
						SourcePage:         item.URL,
						DiscoveryMethod:    "HTML_CRAWL",
						IdentityContext:    identity,
						DiscoveredAt:       time.Now().UTC(),
						CrawlDepth:         item.Depth + 1,
						InScope:            false,
						Classification:     ClassificationOutOfScope,
						Confidence:         "HIGH",
						AccessibilityState: "OUT_OF_SCOPE",
						ExclusionReason:    "Out of assessment scope",
					})
					continue
				}

				// Enqueue if within depth budget and not yet visited
				if item.Depth+1 <= ac.opts.MaxDepth {
					if !visitedURLs[l] {
						visitedURLs[l] = true
						queue = append(queue, crawlQueueItem{
							URL:      l,
							Depth:    item.Depth + 1,
							Referrer: item.URL,
						})
					}
				} else {
					addCoverageGap("LIMIT_REACHED", l, fmt.Sprintf("Max crawl depth (%d) reached", ac.opts.MaxDepth))
				}
			}

			// Process static assets & scripts
			for _, sa := range staticAssets {
				inScopeAsset := ac.scope.IsAllowed(sa.URL)
				if ac.opts.IsAllowed != nil && !ac.opts.IsAllowed(sa.URL) {
					inScopeAsset = false
				}

				if !inScopeAsset {
					addResource(DiscoveredResource{
						ID:                 ComputeResourceID(identity, "GET", sa.URL),
						URL:                sa.URL,
						NormalizedURL:      sa.URL,
						Host:               targetHost,
						Path:               sa.URL,
						HTTPMethod:         "GET",
						AssetType:          sa.Type,
						SourcePage:         item.URL,
						DiscoveryMethod:    "STATIC_LINK",
						IdentityContext:    identity,
						DiscoveredAt:       time.Now().UTC(),
						CrawlDepth:         item.Depth,
						InScope:            false,
						Classification:     ClassificationOutOfScope,
						Confidence:         "HIGH",
						AccessibilityState: "OUT_OF_SCOPE",
					})
					continue
				}

				addResource(DiscoveredResource{
					ID:                 ComputeResourceID(identity, "GET", sa.URL),
					URL:                sa.URL,
					NormalizedURL:      sa.URL,
					Host:               targetHost,
					Path:               sa.URL,
					HTTPMethod:         "GET",
					AssetType:          sa.Type,
					SourcePage:         item.URL,
					DiscoveryMethod:    "STATIC_LINK",
					IdentityContext:    identity,
					DiscoveredAt:       time.Now().UTC(),
					CrawlDepth:         item.Depth,
					InScope:            true,
					Classification:     ClassificationStaticAsset,
					Confidence:         "HIGH",
					AccessibilityState: "REACHABLE",
				})

				// If JavaScript bundle, retrieve and analyze routes
				if sa.Type == AssetJavaScript && !analyzedBundles[sa.URL] {
					analyzedBundles[sa.URL] = true
					ac.analyzeJavaScriptBundle(ctx, client, sa.URL, item.URL, identity, addResource, addCoverageGap, res)
				}
			}
		}
	}

	return res, nil
}

// analyzeJavaScriptBundle downloads and statically inspects a JS bundle for API endpoint candidates.
func (ac *ActiveCrawler) analyzeJavaScriptBundle(
	ctx context.Context,
	client *http.Client,
	jsURL string,
	referrer string,
	identity string,
	addResource func(DiscoveredResource),
	addCoverageGap func(gapType, resource, reason string),
	res *ActiveCrawlResult,
) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jsURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Felix/1.0 (+https://felix-security.org)")
	req.Header.Set("Accept", "*/*")

	res.Summary.TotalRequestsMade++

	resp, err := client.Do(req)
	if err != nil {
		addCoverageGap("BUNDLE_UNRETRIEVABLE", jsURL, fmt.Sprintf("Failed to retrieve script: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		addCoverageGap("BUNDLE_UNRETRIEVABLE", jsURL, fmt.Sprintf("HTTP %d retrieving script bundle", resp.StatusCode))
		return
	}

	lr := io.LimitReader(resp.Body, ac.opts.MaxAssetSize+1)
	content, err := io.ReadAll(lr)
	if err != nil {
		addCoverageGap("BUNDLE_UNRETRIEVABLE", jsURL, fmt.Sprintf("Failed to read script body: %v", err))
		return
	}

	// Add JS bundle to inventory assets
	res.AssetsForInventory = append(res.AssetsForInventory, Asset{
		URL:         jsURL,
		Type:        AssetJavaScript,
		Content:     content,
		Size:        int64(len(content)),
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		InScope:     true,
		Provenance:  ProvenanceStatic,
	})

	// Run AST & heuristic route extraction
	candidates, _, _, warnings := ac.bundle.ExtractFromBundle(content, jsURL)
	for _, w := range warnings {
		addCoverageGap("BUNDLE_WARNING", jsURL, w)
	}

	parsedTarget, _ := url.Parse(ac.opts.TargetURL)
	scopeHost := ""
	if parsedTarget != nil {
		scopeHost = parsedTarget.Host
	}

	for _, cand := range candidates {
		norm := NormalizeRouteCandidate(cand.RawPath, scopeHost)
		if !norm.IsInScope {
			continue
		}

		conf := "MEDIUM"
		if cand.Confidence == ConfidenceConfirmed {
			conf = "HIGH"
		} else if cand.Confidence == ConfidenceHeuristic {
			conf = "LOW"
		}

		method := cand.HTTPMethod
		if method == "" || method == "UNKNOWN" {
			method = "GET"
		}

		fullURL := norm.NormalizedPath
		if parsedTarget != nil {
			if relU, rErr := url.Parse(norm.NormalizedPath); rErr == nil {
				if strings.HasPrefix(norm.NormalizedPath, "/") && strings.HasPrefix(strings.TrimSpace(cand.RawPath), "/") {
					origin := url.URL{Scheme: parsedTarget.Scheme, Host: parsedTarget.Host}
					fullURL = origin.ResolveReference(relU).String()
				} else if strings.HasPrefix(norm.NormalizedPath, "/") {
					// Relative JS route (e.g. "identity/api/auth/login"): keep target path if non-root, otherwise origin root
					if parsedTarget.Path != "" && parsedTarget.Path != "/" && !strings.HasPrefix(cand.RawPath, "/") {
						baseCopy := *parsedTarget
						if !strings.HasSuffix(baseCopy.Path, "/") {
							baseCopy.Path += "/"
						}
						if subRel, sErr := url.Parse(strings.TrimPrefix(norm.NormalizedPath, "/")); sErr == nil {
							fullURL = baseCopy.ResolveReference(subRel).String()
						}
					} else {
						origin := url.URL{Scheme: parsedTarget.Scheme, Host: parsedTarget.Host}
						fullURL = origin.ResolveReference(relU).String()
					}
				}
			}
		}

		classification := ClassificationEndpointCandidate
		exclusionReason := ""
		if isDest, reason := IsDestructiveURL(fullURL, ac.opts.DestructivePatterns); isDest {
			classification = ClassificationExcludedDestructive
			exclusionReason = fmt.Sprintf("Destructive action pattern in JS route: %s", reason)
			addCoverageGap("SAFETY_EXCLUSION", fullURL, exclusionReason)
		}

		addResource(DiscoveredResource{
			ID:                 ComputeResourceID(identity, method, fullURL),
			URL:                fullURL,
			NormalizedURL:      fullURL,
			Host:               scopeHost,
			Path:               norm.NormalizedPath,
			HTTPMethod:         method,
			AssetType:          "api",
			SourcePage:         jsURL,
			DiscoveryMethod:    "JS_ROUTE_CANDIDATE",
			IdentityContext:    identity,
			DiscoveredAt:       cand.DiscoveredAt,
			InScope:            true,
			Classification:     classification,
			Confidence:         conf,
			AccessibilityState: "UNTESTED",
			Evidence:           cand.Evidence,
			ExclusionReason:    exclusionReason,
		})
	}
}

// MultiIdentityCrawlResult consolidates multi-identity discovery findings.
type MultiIdentityCrawlResult struct {
	PerIdentity        map[string]*ActiveCrawlResult `json:"per_identity"`
	CombinedResources  []DiscoveredResource          `json:"combined_resources"`
	VisibilityMatrix   *IdentityVisibilityMatrix     `json:"visibility_matrix"`
	Summary            DiscoverySummary              `json:"summary"`
	CoverageGaps       []CoverageGapRecord           `json:"coverage_gaps"`
	AssetsForInventory []Asset                       `json:"assets_for_inventory"`
}

// CrawlMultiIdentity executes active discovery across multiple identity sessions.
func CrawlMultiIdentity(
	ctx context.Context,
	opts ActiveCrawlOptions,
	idClientMap map[string]*http.Client,
) (*MultiIdentityCrawlResult, error) {
	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		return nil, err
	}

	// Deterministic identity sequence including standard identities
	standardIdentities := []string{"ANONYMOUS", "USER_A", "USER_B", "ADMIN"}
	idSet := make(map[string]bool)
	for _, id := range standardIdentities {
		idSet[id] = true
	}
	for id := range idClientMap {
		idSet[id] = true
	}
	var identities []string
	for id := range idSet {
		identities = append(identities, id)
	}
	sort.Strings(identities)

	res := &MultiIdentityCrawlResult{
		PerIdentity:      make(map[string]*ActiveCrawlResult),
		VisibilityMatrix: NewIdentityVisibilityMatrix(identities...),
	}

	seenCombined := make(map[string]bool)
	seenAssets := make(map[string]bool)

	for _, id := range identities {
		client := idClientMap[id]
		if client == nil {
			continue
		}

		singleRes, err := crawler.CrawlApplication(ctx, client, id)
		if err != nil {
			res.CoverageGaps = append(res.CoverageGaps, CoverageGapRecord{
				Type:            "AUTH_BLOCKED",
				Resource:        opts.TargetURL,
				Reason:          fmt.Sprintf("Crawl under %s failed: %v", id, err),
				IdentityContext: id,
			})
			continue
		}

		res.PerIdentity[id] = singleRes

		// Merge coverage gaps
		res.CoverageGaps = append(res.CoverageGaps, singleRes.CoverageGaps...)

		// Merge into unified visibility matrix
		if singleRes.VisibilityMatrix != nil {
			for rKey, obsMap := range singleRes.VisibilityMatrix.Endpoints {
				for idKey, obs := range obsMap {
					res.VisibilityMatrix.RecordObservation(rKey, idKey, obs)
				}
			}
		}

		// Merge combined resources
		seenSummary := make(map[string]bool)
		for _, dr := range res.CombinedResources {
			seenSummary[fmt.Sprintf("%s:%s", dr.HTTPMethod, dr.NormalizedURL)] = true
		}
		for _, dr := range singleRes.Resources {
			comboKey := fmt.Sprintf("%s:%s:%s", dr.IdentityContext, dr.HTTPMethod, dr.NormalizedURL)
			if !seenCombined[comboKey] {
				seenCombined[comboKey] = true
				res.CombinedResources = append(res.CombinedResources, dr)

				summaryKey := fmt.Sprintf("%s:%s", dr.HTTPMethod, dr.NormalizedURL)
				if !seenSummary[summaryKey] {
					seenSummary[summaryKey] = true
					// Update Summary deduplicated across identities
					switch dr.Classification {
					case ClassificationConfirmedEndpoint:
						res.Summary.TotalConfirmedEndpoints++
						if dr.AssetType == "page" || strings.Contains(dr.ContentType, "html") {
							res.Summary.TotalPagesDiscovered++
						}
					case ClassificationEndpointCandidate:
						res.Summary.TotalEndpointCandidates++
					case ClassificationObservedForm:
						res.Summary.TotalFormsAndInputs++
					case ClassificationStaticAsset:
						res.Summary.TotalStaticAssets++
						if dr.AssetType == AssetJavaScript {
							res.Summary.TotalJavaScriptBundles++
						}
					case ClassificationInaccessible:
						res.Summary.TotalInaccessibleResources++
					case ClassificationExcludedDestructive, ClassificationOutOfScope:
						res.Summary.TotalExcludedResources++
					}
				}
			}
		}

		// Accumulate requests
		res.Summary.TotalRequestsMade += singleRes.Summary.TotalRequestsMade

		// Merge inventory assets (deduplicating by URL)
		for _, a := range singleRes.AssetsForInventory {
			if !seenAssets[a.URL] {
				seenAssets[a.URL] = true
				res.AssetsForInventory = append(res.AssetsForInventory, a)
			}
		}
	}

	// For all discovered routes in the visibility matrix, mark any identity that was
	// not configured or had a nil client as NOT_CONFIGURED
	if res.VisibilityMatrix != nil {
		for _, id := range identities {
			if idClientMap[id] == nil {
				for rKey := range res.VisibilityMatrix.Endpoints {
					if _, exists := res.VisibilityMatrix.Endpoints[rKey][id]; !exists {
						res.VisibilityMatrix.RecordObservation(rKey, id, IdentityRouteObservation{
							Visible:        false,
							StatusCode:     0,
							StatusText:     "NOT_CONFIGURED",
							Classification: "NOT_CONFIGURED",
						})
					}
				}
			}
		}
	}

	return res, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
