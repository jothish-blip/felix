package browser

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"felix/pkg/crawler"
	"github.com/chromedp/chromedp"
)

// CDPDiscoveryDriver implements crawler.BrowserDiscoveryDriver using Phase 1 headless browser components.
type CDPDiscoveryDriver struct {
	AllowLoopback   bool
	AllowPrivateIPs bool
}

// NewCDPDiscoveryDriver returns an instantiated driver.
func NewCDPDiscoveryDriver() *CDPDiscoveryDriver {
	return &CDPDiscoveryDriver{}
}

func init() {
	crawler.RegisterCDPDriver(NewCDPDiscoveryDriver())
}

// Discover satisfies crawler.BrowserDiscoveryDriver.
func (d *CDPDiscoveryDriver) Discover(ctx context.Context, targetURL string, opts crawler.BrowserDiscoveryOptions, scope *crawler.Scope) (*crawler.BrowserDiscoveryResult, error) {
	start := time.Now()
	res := &crawler.BrowserDiscoveryResult{
		Endpoints: make([]crawler.DynamicEndpoint, 0),
	}

	// 1. Initial scope check
	if scope != nil && !scope.IsAllowed(targetURL) {
		res.Inconclusive = true
		res.Reason = fmt.Sprintf("target %s blocked: out of approved crawl scope", targetURL)
		res.Duration = time.Since(start)
		return res, crawler.ErrOutOfScopeNavigation
	}

	// 2. Resolve browser binary
	binPath := opts.BrowserBinary
	if binPath == "" {
		p, err := FindBrowserExecutable()
		if err != nil {
			res.Inconclusive = true
			res.Reason = fmt.Sprintf("CDP browser discovery skipped: %v", err)
			res.Duration = time.Since(start)
			return res, nil
		}
		binPath = p
	}
	res.BinaryUsed = binPath

	// 3. Execution timeout
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 4. Launch browser session
	bCfg := DefaultConfig()
	bCfg.ExecPath = binPath
	if opts.DisableSandbox {
		bCfg.NoSandbox = true
	}

	inst, err := Launch(execCtx, bCfg)
	if err != nil {
		res.Inconclusive = true
		res.Reason = fmt.Sprintf("failed launching browser session: %v", err)
		res.Duration = time.Since(start)
		return res, err
	}
	defer inst.Close()

	// 5. Attach SafeDialer Network Gateway
	gwOpts := GatewayOptions{
		AllowLoopback:   opts.AllowLoopback || d.AllowLoopback,
		AllowPrivateIPs: opts.AllowPrivateIPs || d.AllowPrivateIPs,
	}
	gw, gwErr := AttachNetworkGateway(execCtx, inst, gwOpts)
	if gwErr == nil && gw != nil {
		defer gw.Stop()
	}

	// 6. Attach DOM XSS Instrumenter if enabled
	if opts.EnableDOMXSS {
		dxOpts := DefaultDOMXSSOptions()
		dx, dxErr := AttachDOMXSSInstrumenter(execCtx, inst, dxOpts)
		if dxErr == nil && dx != nil {
			defer dx.Stop()
		}
	}

	// 7. Initial Navigation
	waitReady := 200 * time.Millisecond
	if opts.WaitUntilReady > 0 {
		waitReady = opts.WaitUntilReady
	}
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(waitReady)); err != nil {
		if execCtx.Err() == context.DeadlineExceeded {
			res.Inconclusive = true
			res.Reason = fmt.Sprintf("navigation to %s timed out", targetURL)
			res.Duration = time.Since(start)
			return res, crawler.ErrBrowserTimeout
		}
		res.Inconclusive = true
		res.Reason = fmt.Sprintf("navigation failed: %v", err)
		res.Duration = time.Since(start)
		return res, err
	}

	// 8. Execute SPA State Navigator if enabled
	if opts.EnableSPANavigation {
		spaCfg := DefaultSPANavigatorConfig()
		if opts.Timeout > 0 {
			spaCfg.ExplorationTimeout = opts.Timeout
		}
		spaNav, err := NewSPANavigator(inst, spaCfg)
		if err == nil {
			spaRep, err := spaNav.Explore(execCtx)
			if err == nil && spaRep != nil {
				res.SPANavigation = spaRep
				for _, state := range spaRep.States {
					stateURL := state.URL
					inScope := scope == nil || scope.IsAllowed(stateURL)
					res.Endpoints = append(res.Endpoints, crawler.DynamicEndpoint{
						URL:        stateURL,
						Type:       crawler.AssetUnknown,
						InScope:    inScope,
						Provenance: crawler.ProvenanceBrowser,
						Inferred:   false,
					})
				}
			}
		}
	}

	// 9. Execute DOM Monkey if enabled
	if opts.EnableDOMMonkey {
		monkeyCfg := DefaultMonkeyConfig()
		m, err := NewDOMMonkey(inst, monkeyCfg)
		if err == nil {
			_, _ = m.Execute(execCtx)
		}
	}

	// 10. Execute Storage Audit if enabled
	if opts.EnableStorageAudit {
		auditor, err := NewStorageAuditor(inst, DefaultStorageAuditConfig())
		if err == nil {
			storageRep, err := auditor.Audit(execCtx)
			if err == nil {
				res.StorageAudit = storageRep
			}
		}
	}

	// 11. Extract rendered DOM and DOM endpoints
	renderedHTML, _ := chromedp.Run(inst.Ctx, chromedp.Evaluate[string]("document.documentElement.outerHTML"))
	res.RenderedHTML = renderedHTML

	if parsedBase, err := url.Parse(targetURL); err == nil {
		domEndpoints := crawler.ExtractDynamicEndpoints(renderedHTML, parsedBase, scope)
		res.Endpoints = append(res.Endpoints, domEndpoints...)
	}

	// 12. Extract intercepted API routes from Network Gateway
	if gw != nil {
		for _, apiRoute := range gw.GetAPIRoutes() {
			inScope := scope == nil || scope.IsAllowed(apiRoute)
			res.Endpoints = append(res.Endpoints, crawler.DynamicEndpoint{
				URL:        apiRoute,
				Type:       crawler.AssetUnknown,
				InScope:    inScope,
				Provenance: crawler.ProvenanceBrowser,
				Inferred:   false,
			})
		}
	}

	res.Duration = time.Since(start)
	return res, nil
}
