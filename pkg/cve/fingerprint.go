package cve

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"felix/pkg/crawler"
	"golang.org/x/net/html"
)

// ConfidenceLevel represents the certainty of component identification.
type ConfidenceLevel string

const (
	ConfidenceConfirmed      ConfidenceLevel = "CONFIRMED"
	ConfidenceConfirmedNoVer ConfidenceLevel = "CONFIRMED_UNKNOWN_VERSION"
	ConfidenceProbable       ConfidenceLevel = "PROBABLE"
	ConfidenceUnidentified   ConfidenceLevel = "UNIDENTIFIED"
)

// DetectionSource represents the origin channel of the fingerprint evidence.
type DetectionSource string

const (
	SourceHeader    DetectionSource = "HEADER"
	SourceCookie    DetectionSource = "COOKIE"
	SourceMetaTag   DetectionSource = "META_TAG"
	SourceDOMMarker DetectionSource = "DOM_MARKER"
	SourceJSAsset   DetectionSource = "JAVASCRIPT_ASSET"
	SourceAPI       DetectionSource = "API_ENDPOINT"
)

// ComponentFinding represents a single detected technology component.
type ComponentFinding struct {
	ComponentName string            `json:"component_name"`
	Vendor        string            `json:"vendor"`
	Product       string            `json:"product"`
	Version       string            `json:"version,omitempty"`
	CPE23         string            `json:"cpe_23,omitempty"`
	Part          string            `json:"part"` // "a" (application), "o" (os), "h" (hardware)
	Confidence    ConfidenceLevel   `json:"confidence"`
	Sources       []DetectionSource `json:"sources"`
	Evidence      []string          `json:"evidence"`
	AssetURL      string            `json:"asset_url,omitempty"`
}

// FingerprintResult contains the aggregated technological fingerprint of a target.
type FingerprintResult struct {
	TargetURL             string             `json:"target_url"`
	Components            []ComponentFinding `json:"components"`
	IdentifiedCount       int                `json:"identified_count"`
	ConfirmedVersionCount int                `json:"confirmed_version_count"`
	CPEAssignedCount      int                `json:"cpe_assigned_count"`
	UnresolvedCount       int                `json:"unresolved_count"`
}

// JSSignature holds known release metadata for verifiable asset hashes.
type JSSignature struct {
	Vendor      string
	Product     string
	Version     string
	CPEPart     string
	Description string
}

// FingerprinterConfig provides configuration options for the fingerprinter engine.
type FingerprinterConfig struct {
	HTTPClient       *http.Client
	MaxAssetBytes    int64
	AssetTimeout     time.Duration
	AllowedOrigins   []string
	EnableLiveAssets bool
}

// Fingerprinter is the core Phase 4.1 technology and version fingerprinting engine.
type Fingerprinter struct {
	client           *http.Client
	maxAssetBytes    int64
	assetTimeout     time.Duration
	allowedOrigins   map[string]bool
	enableLiveAssets bool
	jsRegistry       map[string]JSSignature
}

// NewFingerprinter constructs a configured Fingerprinter instance.
func NewFingerprinter(cfg FingerprinterConfig) *Fingerprinter {
	client := cfg.HTTPClient
	if client == nil {
		safeTransport := crawler.NewSafeTransport(crawler.SafeTransportOptions{
			AllowLoopback:   true,
			AllowPrivateIPs: true,
			Timeout:         10 * time.Second,
		})
		jar, _ := cookiejar.New(nil)
		client = &http.Client{
			Transport: safeTransport,
			Timeout:   10 * time.Second,
			Jar:       jar,
		}
	} else if client.Jar == nil {
		jar, _ := cookiejar.New(nil)
		client.Jar = jar
	}

	maxBytes := cfg.MaxAssetBytes
	if maxBytes <= 0 {
		maxBytes = 2 * 1024 * 1024 // 2 MB bound
	}

	timeout := cfg.AssetTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	allowedOrigins := make(map[string]bool)
	for _, o := range cfg.AllowedOrigins {
		if norm, err := normalizeOrigin(o); err == nil {
			allowedOrigins[norm] = true
		}
	}

	fp := &Fingerprinter{
		client:           client,
		maxAssetBytes:    maxBytes,
		assetTimeout:     timeout,
		allowedOrigins:   allowedOrigins,
		enableLiveAssets: cfg.EnableLiveAssets,
		jsRegistry:       make(map[string]JSSignature),
	}

	fp.initJSRegistry()
	return fp
}

// initJSRegistry initializes the trusted release hashes for JavaScript asset fingerprinting.
func (f *Fingerprinter) initJSRegistry() {
	// Standard verified release hashes (SHA-256 of official minified release distributions)
	// NodeGoat jQuery v1.10.2
	f.jsRegistry["fa411409e767595b83bf12f7204d69a856031ec9466998358316f6cbbfedd8a6"] = JSSignature{
		Vendor:      "jquery",
		Product:     "jquery",
		Version:     "1.10.2",
		CPEPart:     "a",
		Description: "jQuery v1.10.2 Official Release",
	}
	// DVGA jQuery v3.5.1
	f.jsRegistry["f36844906ad2309877aae3121b87fb15b9e09803cb4c333adc7e1e35ac92e14b"] = JSSignature{
		Vendor:      "jquery",
		Product:     "jquery",
		Version:     "3.5.1",
		CPEPart:     "a",
		Description: "jQuery v3.5.1 Official Release",
	}
	// jQuery v3.6.0
	f.jsRegistry["437937dae61c32c253456885df4426511a511516e8ea36ff31a9865ad39d1bfa"] = JSSignature{
		Vendor:      "jquery",
		Product:     "jquery",
		Version:     "3.6.0",
		CPEPart:     "a",
		Description: "jQuery v3.6.0 Official Release",
	}
	// jQuery v3.7.1
	f.jsRegistry["b02fed7d1cf7463fca374d440ad858a74e5033bc65b82260216bd4aa1a4c9c1b"] = JSSignature{
		Vendor:      "jquery",
		Product:     "jquery",
		Version:     "3.7.1",
		CPEPart:     "a",
		Description: "jQuery v3.7.1 Official Release",
	}
}

// RegisterJSSignature allows adding trusted asset release hashes at runtime.
func (f *Fingerprinter) RegisterJSSignature(sha256Hex string, sig JSSignature) {
	f.jsRegistry[strings.ToLower(strings.TrimSpace(sha256Hex))] = sig
}

// FormatCPE23 formats component coordinates into a canonical CPE 2.3 string.
// Schema: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
func FormatCPE23(part, vendor, product, version string) string {
	if part == "" {
		part = "a"
	}
	cleanVendor := escapeCPE(sanitizeCPEString(vendor))
	cleanProduct := escapeCPE(sanitizeCPEString(product))
	cleanVersion := "*"
	if version != "" && version != "*" {
		cleanVersion = escapeCPE(sanitizeCPEString(version))
	}
	return fmt.Sprintf("cpe:2.3:%s:%s:%s:%s:*:*:*:*:*:*:*", part, cleanVendor, cleanProduct, cleanVersion)
}

func sanitizeCPEString(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.ReplaceAll(s, " ", "_")
	return s
}

func escapeCPE(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch ch {
		case ':', '\\', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '+', ',', '/', ';', '<', '=', '>', '@', '[', ']', '^', '`', '{', '|', '}', '~':
			b.WriteByte('\\')
			b.WriteByte(ch)
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}

// FingerprintHTTPResponse analyzes a single HTTP response (headers, cookies, and body).
func (f *Fingerprinter) FingerprintHTTPResponse(ctx context.Context, targetURL string, resp *http.Response, bodyBytes []byte) (*FingerprintResult, error) {
	if resp == nil {
		return nil, errors.New("nil http response provided to fingerprinter")
	}

	resultMap := make(map[string]*ComponentFinding)

	// 1. Analyze HTTP Response Headers
	f.fingerprintHeaders(resp.Header, resultMap)

	// 2. Analyze Cookies
	allCookies := resp.Cookies()
	if f.client.Jar != nil {
		if parsed, err := url.Parse(targetURL); err == nil {
			jarCookies := f.client.Jar.Cookies(parsed)
			allCookies = append(allCookies, jarCookies...)
		}
	}
	f.fingerprintCookies(allCookies, resultMap)

	// 3. Analyze HTML DOM, Meta Tags, and Markers
	if len(bodyBytes) > 0 {
		f.fingerprintHTML(targetURL, bodyBytes, resultMap)
	}

	// 4. Discover and Fingerprint JavaScript Assets if enabled
	if f.enableLiveAssets && len(bodyBytes) > 0 {
		f.fingerprintAssets(ctx, targetURL, bodyBytes, resultMap)
	}

	// 5. Query well-known technology endpoints if within scope
	f.probeKnownEndpoints(ctx, targetURL, resultMap)

	return f.buildResult(targetURL, resultMap), nil
}

// FingerprintURL performs an HTTP GET against targetURL and fingerprints the response.
func (f *Fingerprinter) FingerprintURL(ctx context.Context, targetURL string) (*FingerprintResult, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	if err := f.validateScopeAndSSRF(parsed); err != nil {
		return nil, fmt.Errorf("target scope rejection: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("target HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, f.maxAssetBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return f.FingerprintHTTPResponse(ctx, targetURL, resp, bodyBytes)
}

// -------------------------------------------------------------------------------------------------
// Subsystem A: HTTP Header Fingerprinting
// -------------------------------------------------------------------------------------------------

var (
	reServerWerkzeug  = regexp.MustCompile(`(?i)werkzeug/(\d+[\.\d\w\-_]+)`)
	reServerPython    = regexp.MustCompile(`(?i)python/(\d+[\.\d\w\-_]+)`)
	reServerApache    = regexp.MustCompile(`(?i)apache(?:/(\d+[\.\d\w\-_]+))?`)
	reServerNginx     = regexp.MustCompile(`(?i)nginx(?:/(\d+[\.\d\w\-_]+))?`)
	reServerOpenResty = regexp.MustCompile(`(?i)openresty(?:/(\d+[\.\d\w\-_]+))?`)
	reServerJetty     = regexp.MustCompile(`(?i)jetty(?:\((\d+[\.\d\w\-_]+)\))?`)
	reServerIIS       = regexp.MustCompile(`(?i)microsoft-iis(?:/(\d+[\.\d\w\-_]+))?`)
	reServerGunicorn  = regexp.MustCompile(`(?i)gunicorn(?:/(\d+[\.\d\w\-_]+))?`)
	reServerTomcat    = regexp.MustCompile(`(?i)(?:apache-tomcat|tomcat)(?:/(\d+[\.\d\w\-_]+))?`)

	rePHPVer    = regexp.MustCompile(`(?i)php(?:/(\d+[\.\d\w\-_]+))?`)
	reAspNetVer = regexp.MustCompile(`(?i)(\d+[\.\d\w\-_]+)`)
)

func (f *Fingerprinter) fingerprintHeaders(headers http.Header, res map[string]*ComponentFinding) {
	for name, values := range headers {
		for _, val := range values {
			valClean := strings.TrimSpace(val)
			if valClean == "" {
				continue
			}

			nameLower := strings.ToLower(name)
			switch nameLower {
			case "server":
				f.parseServerHeader(valClean, res)

			case "x-powered-by":
				f.parseXPoweredByHeader(valClean, res)

			case "x-aspnet-version":
				if m := reAspNetVer.FindStringSubmatch(valClean); len(m) > 1 {
					f.mergeComponent(res, ComponentFinding{
						ComponentName: "ASP.NET",
						Vendor:        "microsoft",
						Product:       "asp.net",
						Version:       m[1],
						Part:          "a",
						Confidence:    ConfidenceConfirmed,
						Sources:       []DetectionSource{SourceHeader},
						Evidence:      []string{fmt.Sprintf("Header X-AspNet-Version: %s", valClean)},
					})
				}

			case "x-generator":
				f.parseGeneratorString(valClean, SourceHeader, res)

			case "x-recruiting":
				if strings.Contains(valClean, "/#/jobs") {
					f.mergeComponent(res, ComponentFinding{
						ComponentName: "OWASP Juice Shop",
						Vendor:        "owasp",
						Product:       "juice-shop",
						Part:          "a",
						Confidence:    ConfidenceConfirmedNoVer,
						Sources:       []DetectionSource{SourceHeader},
						Evidence:      []string{fmt.Sprintf("Header X-Recruiting: %s", valClean)},
					})
				}
			}
		}
	}
}

func (f *Fingerprinter) parseServerHeader(serverVal string, res map[string]*ComponentFinding) {
	evidence := fmt.Sprintf("Header Server: %s", serverVal)

	// Werkzeug
	if m := reServerWerkzeug.FindStringSubmatch(serverVal); len(m) > 1 {
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "Werkzeug",
			Vendor:        "palletsprojects",
			Product:       "werkzeug",
			Version:       m[1],
			Part:          "a",
			Confidence:    ConfidenceConfirmed,
			Sources:       []DetectionSource{SourceHeader},
			Evidence:      []string{evidence},
		})
	}

	// Python
	if m := reServerPython.FindStringSubmatch(serverVal); len(m) > 1 {
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "Python",
			Vendor:        "python",
			Product:       "python",
			Version:       m[1],
			Part:          "a",
			Confidence:    ConfidenceConfirmed,
			Sources:       []DetectionSource{SourceHeader},
			Evidence:      []string{evidence},
		})
	}

	// OpenResty
	if m := reServerOpenResty.FindStringSubmatch(serverVal); len(m) > 0 {
		ver := ""
		conf := ConfidenceConfirmedNoVer
		if len(m) > 1 && m[1] != "" {
			ver = m[1]
			conf = ConfidenceConfirmed
		}
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "OpenResty",
			Vendor:        "openresty",
			Product:       "openresty",
			Version:       ver,
			Part:          "a",
			Confidence:    conf,
			Sources:       []DetectionSource{SourceHeader},
			Evidence:      []string{evidence},
		})
	} else if m := reServerNginx.FindStringSubmatch(serverVal); len(m) > 0 {
		// Nginx
		ver := ""
		conf := ConfidenceConfirmedNoVer
		if len(m) > 1 && m[1] != "" {
			ver = m[1]
			conf = ConfidenceConfirmed
		}
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "nginx",
			Vendor:        "f5",
			Product:       "nginx",
			Version:       ver,
			Part:          "a",
			Confidence:    conf,
			Sources:       []DetectionSource{SourceHeader},
			Evidence:      []string{evidence},
		})
	}

	// Apache HTTP Server
	if m := reServerApache.FindStringSubmatch(serverVal); len(m) > 0 {
		ver := ""
		conf := ConfidenceConfirmedNoVer
		if len(m) > 1 && m[1] != "" {
			ver = m[1]
			conf = ConfidenceConfirmed
		}
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "Apache HTTP Server",
			Vendor:        "apache",
			Product:       "http_server",
			Version:       ver,
			Part:          "a",
			Confidence:    conf,
			Sources:       []DetectionSource{SourceHeader},
			Evidence:      []string{evidence},
		})
	}

	// Microsoft IIS
	if m := reServerIIS.FindStringSubmatch(serverVal); len(m) > 0 {
		ver := ""
		conf := ConfidenceConfirmedNoVer
		if len(m) > 1 && m[1] != "" {
			ver = m[1]
			conf = ConfidenceConfirmed
		}
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "Microsoft IIS",
			Vendor:        "microsoft",
			Product:       "internet_information_services",
			Version:       ver,
			Part:          "a",
			Confidence:    conf,
			Sources:       []DetectionSource{SourceHeader},
			Evidence:      []string{evidence},
		})
	}

	// Eclipse Jetty
	if m := reServerJetty.FindStringSubmatch(serverVal); len(m) > 0 {
		ver := ""
		conf := ConfidenceConfirmedNoVer
		if len(m) > 1 && m[1] != "" {
			ver = m[1]
			conf = ConfidenceConfirmed
		}
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "Eclipse Jetty",
			Vendor:        "eclipse",
			Product:       "jetty",
			Version:       ver,
			Part:          "a",
			Confidence:    conf,
			Sources:       []DetectionSource{SourceHeader},
			Evidence:      []string{evidence},
		})
	}

	// Gunicorn
	if m := reServerGunicorn.FindStringSubmatch(serverVal); len(m) > 0 {
		ver := ""
		conf := ConfidenceConfirmedNoVer
		if len(m) > 1 && m[1] != "" {
			ver = m[1]
			conf = ConfidenceConfirmed
		}
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "Gunicorn",
			Vendor:        "gunicorn",
			Product:       "gunicorn",
			Version:       ver,
			Part:          "a",
			Confidence:    conf,
			Sources:       []DetectionSource{SourceHeader},
			Evidence:      []string{evidence},
		})
	}

	// Apache Tomcat
	if m := reServerTomcat.FindStringSubmatch(serverVal); len(m) > 0 {
		ver := ""
		conf := ConfidenceConfirmedNoVer
		if len(m) > 1 && m[1] != "" {
			ver = m[1]
			conf = ConfidenceConfirmed
		}
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "Apache Tomcat",
			Vendor:        "apache",
			Product:       "tomcat",
			Version:       ver,
			Part:          "a",
			Confidence:    conf,
			Sources:       []DetectionSource{SourceHeader},
			Evidence:      []string{evidence},
		})
	}
}

func (f *Fingerprinter) parseXPoweredByHeader(val string, res map[string]*ComponentFinding) {
	evidence := fmt.Sprintf("Header X-Powered-By: %s", val)

	// Express
	if strings.Contains(strings.ToLower(val), "express") {
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "Express.js",
			Vendor:        "expressjs",
			Product:       "express",
			Part:          "a",
			Confidence:    ConfidenceConfirmedNoVer,
			Sources:       []DetectionSource{SourceHeader},
			Evidence:      []string{evidence},
		})
	}

	// PHP
	if m := rePHPVer.FindStringSubmatch(val); len(m) > 0 {
		ver := ""
		conf := ConfidenceConfirmedNoVer
		if len(m) > 1 && m[1] != "" {
			ver = m[1]
			conf = ConfidenceConfirmed
		}
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "PHP",
			Vendor:        "php",
			Product:       "php",
			Version:       ver,
			Part:          "a",
			Confidence:    conf,
			Sources:       []DetectionSource{SourceHeader},
			Evidence:      []string{evidence},
		})
	}

	// ASP.NET
	if strings.Contains(strings.ToLower(val), "asp.net") {
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "ASP.NET",
			Vendor:        "microsoft",
			Product:       "asp.net",
			Part:          "a",
			Confidence:    ConfidenceConfirmedNoVer,
			Sources:       []DetectionSource{SourceHeader},
			Evidence:      []string{evidence},
		})
	}

	// Next.js
	if strings.Contains(strings.ToLower(val), "next.js") {
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "Next.js",
			Vendor:        "vercel",
			Product:       "next.js",
			Part:          "a",
			Confidence:    ConfidenceConfirmedNoVer,
			Sources:       []DetectionSource{SourceHeader},
			Evidence:      []string{evidence},
		})
	}
}

// -------------------------------------------------------------------------------------------------
// Subsystem B: Cookie Fingerprinting
// -------------------------------------------------------------------------------------------------

func (f *Fingerprinter) fingerprintCookies(cookies []*http.Cookie, res map[string]*ComponentFinding) {
	for _, c := range cookies {
		cName := strings.TrimSpace(c.Name)
		evidence := fmt.Sprintf("Cookie name: %s", cName)

		switch {
		case strings.EqualFold(cName, "JSESSIONID"):
			f.mergeComponent(res, ComponentFinding{
				ComponentName: "Java Servlet / Container Session",
				Vendor:        "oracle",
				Product:       "java_servlet",
				Part:          "a",
				Confidence:    ConfidenceConfirmedNoVer,
				Sources:       []DetectionSource{SourceCookie},
				Evidence:      []string{evidence},
			})

		case strings.EqualFold(cName, "connect.sid"):
			f.mergeComponent(res, ComponentFinding{
				ComponentName: "Express.js Session",
				Vendor:        "expressjs",
				Product:       "express-session",
				Part:          "a",
				Confidence:    ConfidenceConfirmedNoVer,
				Sources:       []DetectionSource{SourceCookie},
				Evidence:      []string{evidence},
			})

		case strings.EqualFold(cName, "PHPSESSID"):
			f.mergeComponent(res, ComponentFinding{
				ComponentName: "PHP Session",
				Vendor:        "php",
				Product:       "php",
				Part:          "a",
				Confidence:    ConfidenceConfirmedNoVer,
				Sources:       []DetectionSource{SourceCookie},
				Evidence:      []string{evidence},
			})

		case strings.EqualFold(cName, "csrftoken"):
			f.mergeComponent(res, ComponentFinding{
				ComponentName: "Django Framework",
				Vendor:        "djangoproject",
				Product:       "django",
				Part:          "a",
				Confidence:    ConfidenceConfirmedNoVer,
				Sources:       []DetectionSource{SourceCookie},
				Evidence:      []string{evidence},
			})

		case strings.HasPrefix(strings.ToLower(cName), "env") && strings.Contains(strings.ToLower(c.Value), "graphiql"):
			f.mergeComponent(res, ComponentFinding{
				ComponentName: "Damn Vulnerable GraphQL Application",
				Vendor:        "dolevf",
				Product:       "damn_vulnerable_graphql_application",
				Part:          "a",
				Confidence:    ConfidenceConfirmedNoVer,
				Sources:       []DetectionSource{SourceCookie},
				Evidence:      []string{fmt.Sprintf("Cookie env: %s", c.Value)},
			})

		case strings.EqualFold(cName, "laravel_session"):
			f.mergeComponent(res, ComponentFinding{
				ComponentName: "Laravel",
				Vendor:        "laravel",
				Product:       "laravel",
				Part:          "a",
				Confidence:    ConfidenceConfirmedNoVer,
				Sources:       []DetectionSource{SourceCookie},
				Evidence:      []string{evidence},
			})
		}
	}
}

// -------------------------------------------------------------------------------------------------
// Subsystem C: HTML DOM and Meta Tag Fingerprinting
// -------------------------------------------------------------------------------------------------

func (f *Fingerprinter) fingerprintHTML(targetURL string, bodyBytes []byte, res map[string]*ComponentFinding) {
	doc, err := html.Parse(bytes.NewReader(bodyBytes))
	if err != nil {
		// Fallback to raw string heuristics if HTML is malformed
		f.fingerprintRawHTML(targetURL, string(bodyBytes), res)
		return
	}

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch strings.ToLower(n.Data) {
			case "meta":
				f.parseMetaTagNode(n, res)

			case "title":
				if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
					f.parseTitleText(n.FirstChild.Data, res)
				}

			case "app-root":
				f.mergeComponent(res, ComponentFinding{
					ComponentName: "Angular Framework",
					Vendor:        "angular",
					Product:       "angular",
					Part:          "a",
					Confidence:    ConfidenceConfirmedNoVer,
					Sources:       []DetectionSource{SourceDOMMarker},
					Evidence:      []string{"DOM custom element: <app-root>"},
				})

			case "input":
				for _, a := range n.Attr {
					if strings.Contains(strings.ToLower(a.Val), "dummy_for_thymeleaf_parser") {
						f.mergeComponent(res, ComponentFinding{
							ComponentName: "Thymeleaf Template Engine",
							Vendor:        "thymeleaf",
							Product:       "thymeleaf",
							Part:          "a",
							Confidence:    ConfidenceConfirmedNoVer,
							Sources:       []DetectionSource{SourceDOMMarker},
							Evidence:      []string{"DOM attribute dummy_for_thymeleaf_parser in <input>"},
						})
					}
				}

			case "a", "form":
				for _, a := range n.Attr {
					if strings.Contains(a.Val, ".mvc") || strings.Contains(a.Val, "/WebGoat/") {
						f.mergeComponent(res, ComponentFinding{
							ComponentName: "Spring Framework MVC",
							Vendor:        "vmware",
							Product:       "spring_framework",
							Part:          "a",
							Confidence:    ConfidenceConfirmedNoVer,
							Sources:       []DetectionSource{SourceDOMMarker},
							Evidence:      []string{fmt.Sprintf("Spring MVC endpoint pattern in %s: %s", n.Data, a.Val)},
						})
						f.mergeComponent(res, ComponentFinding{
							ComponentName: "OWASP WebGoat",
							Vendor:        "owasp",
							Product:       "webgoat",
							Part:          "a",
							Confidence:    ConfidenceConfirmedNoVer,
							Sources:       []DetectionSource{SourceDOMMarker},
							Evidence:      []string{fmt.Sprintf("WebGoat route pattern in %s: %s", n.Data, a.Val)},
						})
					}
				}
			}

			// Check for React markers
			for _, a := range n.Attr {
				if a.Key == "data-reactroot" || a.Key == "data-reactid" {
					f.mergeComponent(res, ComponentFinding{
						ComponentName: "React",
						Vendor:        "facebook",
						Product:       "react",
						Part:          "a",
						Confidence:    ConfidenceConfirmedNoVer,
						Sources:       []DetectionSource{SourceDOMMarker},
						Evidence:      []string{fmt.Sprintf("React DOM attribute: %s", a.Key)},
					})
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	traverse(doc)
	f.fingerprintRawHTML(targetURL, string(bodyBytes), res)
}

func (f *Fingerprinter) parseMetaTagNode(n *html.Node, res map[string]*ComponentFinding) {
	var name, content string
	for _, a := range n.Attr {
		k := strings.ToLower(a.Key)
		if k == "name" || k == "property" {
			name = a.Val
		} else if k == "content" {
			content = a.Val
		}
	}

	nameLower := strings.ToLower(name)
	switch nameLower {
	case "generator":
		f.parseGeneratorString(content, SourceMetaTag, res)

	case "description":
		if strings.Contains(content, "OWASP NodeGoat Project") {
			f.mergeComponent(res, ComponentFinding{
				ComponentName: "OWASP NodeGoat",
				Vendor:        "owasp",
				Product:       "nodegoat",
				Part:          "a",
				Confidence:    ConfidenceConfirmedNoVer,
				Sources:       []DetectionSource{SourceMetaTag},
				Evidence:      []string{fmt.Sprintf("Meta description: %s", content)},
			})
		}
		if strings.Contains(content, "Damn Vulnerable GraphQL Application") {
			f.mergeComponent(res, ComponentFinding{
				ComponentName: "Damn Vulnerable GraphQL Application",
				Vendor:        "dolevf",
				Product:       "damn_vulnerable_graphql_application",
				Part:          "a",
				Confidence:    ConfidenceConfirmedNoVer,
				Sources:       []DetectionSource{SourceMetaTag},
				Evidence:      []string{fmt.Sprintf("Meta description: %s", content)},
			})
		}
		if strings.Contains(content, "Probably the most modern and sophisticated insecure web application") {
			f.mergeComponent(res, ComponentFinding{
				ComponentName: "OWASP Juice Shop",
				Vendor:        "owasp",
				Product:       "juice-shop",
				Part:          "a",
				Confidence:    ConfidenceConfirmedNoVer,
				Sources:       []DetectionSource{SourceMetaTag},
				Evidence:      []string{fmt.Sprintf("Meta description: %s", content)},
			})
		}

	case "version":
		// Check if NodeGoat version tag
		cleanVer := strings.TrimPrefix(strings.TrimSpace(content), "v")
		if cleanVer != "" {
			f.mergeComponent(res, ComponentFinding{
				ComponentName: "OWASP NodeGoat",
				Vendor:        "owasp",
				Product:       "nodegoat",
				Version:       cleanVer,
				Part:          "a",
				Confidence:    ConfidenceConfirmed,
				Sources:       []DetectionSource{SourceMetaTag},
				Evidence:      []string{fmt.Sprintf("Meta version: %s", content)},
			})
		}
	}
}

func (f *Fingerprinter) parseTitleText(title string, res map[string]*ComponentFinding) {
	titleClean := strings.TrimSpace(title)
	evidence := fmt.Sprintf("HTML title: %s", titleClean)

	if strings.Contains(titleClean, "OWASP Juice Shop") {
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "OWASP Juice Shop",
			Vendor:        "owasp",
			Product:       "juice-shop",
			Part:          "a",
			Confidence:    ConfidenceConfirmedNoVer,
			Sources:       []DetectionSource{SourceDOMMarker},
			Evidence:      []string{evidence},
		})
	}

	if strings.Contains(titleClean, "OWASP Node Goat") {
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "OWASP NodeGoat",
			Vendor:        "owasp",
			Product:       "nodegoat",
			Part:          "a",
			Confidence:    ConfidenceConfirmedNoVer,
			Sources:       []DetectionSource{SourceDOMMarker},
			Evidence:      []string{evidence},
		})
	}

	if strings.Contains(titleClean, "Damn Vulnerable GraphQL Application") {
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "Damn Vulnerable GraphQL Application",
			Vendor:        "dolevf",
			Product:       "damn_vulnerable_graphql_application",
			Part:          "a",
			Confidence:    ConfidenceConfirmedNoVer,
			Sources:       []DetectionSource{SourceDOMMarker},
			Evidence:      []string{evidence},
		})
	}
}

func (f *Fingerprinter) parseGeneratorString(gen string, src DetectionSource, res map[string]*ComponentFinding) {
	evidence := fmt.Sprintf("Generator: %s", gen)
	genLower := strings.ToLower(gen)

	var reGenVer = regexp.MustCompile(`(?i)(wordpress|drupal|joomla|ghost|gatsby|hugo)[ /](\d+[\.\d\w\-_]+)`)
	if m := reGenVer.FindStringSubmatch(gen); len(m) > 2 {
		product := strings.ToLower(m[1])
		vendor := product
		if product == "hugo" {
			vendor = "gohugo"
		} else if product == "gatsby" {
			vendor = "gatsbyjs"
		}
		f.mergeComponent(res, ComponentFinding{
			ComponentName: strings.Title(product),
			Vendor:        vendor,
			Product:       product,
			Version:       m[2],
			Part:          "a",
			Confidence:    ConfidenceConfirmed,
			Sources:       []DetectionSource{src},
			Evidence:      []string{evidence},
		})
		return
	}

	if strings.Contains(genLower, "wordpress") {
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "WordPress",
			Vendor:        "wordpress",
			Product:       "wordpress",
			Part:          "a",
			Confidence:    ConfidenceConfirmedNoVer,
			Sources:       []DetectionSource{src},
			Evidence:      []string{evidence},
		})
	}
}

func (f *Fingerprinter) fingerprintRawHTML(targetURL, rawHTML string, res map[string]*ComponentFinding) {
	// Check for VAmPI JSON welcome signature
	if strings.Contains(rawHTML, "VAmPI the Vulnerable API") {
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "VAmPI Vulnerable API",
			Vendor:        "vampi_project",
			Product:       "vampi",
			Part:          "a",
			Confidence:    ConfidenceConfirmedNoVer,
			Sources:       []DetectionSource{SourceDOMMarker},
			Evidence:      []string{"Body signature: 'VAmPI the Vulnerable API'"},
		})
	}

	// Check for DVGA about page version signature
	var reDVGAVer = regexp.MustCompile(`<h4>Current Version</h4>\s*<p>(\d+[\.\d\w\-_]+)</p>`)
	if m := reDVGAVer.FindStringSubmatch(rawHTML); len(m) > 1 {
		f.mergeComponent(res, ComponentFinding{
			ComponentName: "Damn Vulnerable GraphQL Application",
			Vendor:        "dolevf",
			Product:       "damn_vulnerable_graphql_application",
			Version:       m[1],
			Part:          "a",
			Confidence:    ConfidenceConfirmed,
			Sources:       []DetectionSource{SourceDOMMarker},
			Evidence:      []string{fmt.Sprintf("HTML version block: %s", m[1])},
		})
	}
}

// -------------------------------------------------------------------------------------------------
// Subsystem D: JavaScript & CSS Asset Fingerprinting
// -------------------------------------------------------------------------------------------------

var reBootstrapVer = regexp.MustCompile(`(?i)Bootstrap\s+v(\d+[\.\d\w\-_]+)`)

func (f *Fingerprinter) fingerprintAssets(ctx context.Context, targetURL string, bodyBytes []byte, res map[string]*ComponentFinding) {
	assetURLs := f.extractAssetURLs(targetURL, bodyBytes)

	for _, aURL := range assetURLs {
		parsedAsset, err := url.Parse(aURL)
		if err != nil {
			continue
		}

		// Security: Validate scope and SSRF on each asset URL
		if err := f.validateScopeAndSSRF(parsedAsset); err != nil {
			continue
		}

		reqCtx, cancel := context.WithTimeout(ctx, f.assetTimeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, aURL, nil)
		if err != nil {
			cancel()
			continue
		}

		resp, err := f.client.Do(req)
		if err != nil {
			cancel()
			continue
		}

		assetData, err := io.ReadAll(io.LimitReader(resp.Body, f.maxAssetBytes))
		resp.Body.Close()
		cancel()

		if err != nil || len(assetData) == 0 {
			continue
		}

		// 1. Compute SHA-256 Hash
		sum := sha256.Sum256(assetData)
		sumHex := hex.EncodeToString(sum[:])

		// 2. Match against trusted signature registry
		if sig, ok := f.jsRegistry[sumHex]; ok {
			f.mergeComponent(res, ComponentFinding{
				ComponentName: strings.Title(sig.Product),
				Vendor:        sig.Vendor,
				Product:       sig.Product,
				Version:       sig.Version,
				Part:          sig.CPEPart,
				Confidence:    ConfidenceConfirmed,
				Sources:       []DetectionSource{SourceJSAsset},
				Evidence:      []string{fmt.Sprintf("SHA-256 match %s (%s): %s", sumHex, sig.Description, aURL)},
				AssetURL:      aURL,
			})
			continue
		}

		// 3. Inspect asset header comments for verified library releases (e.g. Bootstrap)
		headText := string(assetData)
		if len(headText) > 2048 {
			headText = headText[:2048]
		}
		if m := reBootstrapVer.FindStringSubmatch(headText); len(m) > 1 {
			f.mergeComponent(res, ComponentFinding{
				ComponentName: "Bootstrap",
				Vendor:        "getbootstrap",
				Product:       "bootstrap",
				Version:       m[1],
				Part:          "a",
				Confidence:    ConfidenceConfirmed,
				Sources:       []DetectionSource{SourceJSAsset},
				Evidence:      []string{fmt.Sprintf("Asset header banner %s: %s", m[0], aURL)},
				AssetURL:      aURL,
			})
		}
	}
}

func (f *Fingerprinter) extractAssetURLs(baseURL string, bodyBytes []byte) []string {
	var urls []string
	seen := make(map[string]bool)

	doc, err := html.Parse(bytes.NewReader(bodyBytes))
	if err != nil {
		return urls
	}

	baseParsed, err := url.Parse(baseURL)
	if err != nil {
		return urls
	}

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode {
			var attrURL string
			if n.Data == "script" {
				for _, a := range n.Attr {
					if a.Key == "src" {
						attrURL = a.Val
						break
					}
				}
			} else if n.Data == "link" {
				var isCSS bool
				var href string
				for _, a := range n.Attr {
					if a.Key == "rel" && strings.Contains(strings.ToLower(a.Val), "stylesheet") {
						isCSS = true
					}
					if a.Key == "href" {
						href = a.Val
					}
				}
				if isCSS {
					attrURL = href
				}
			}

			if attrURL != "" && !strings.HasPrefix(attrURL, "data:") {
				resolved := resolveURL(baseParsed, attrURL)
				if resolved != "" && !seen[resolved] {
					seen[resolved] = true
					urls = append(urls, resolved)
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	traverse(doc)
	return urls
}

// -------------------------------------------------------------------------------------------------
// Subsystem E: API & Probe Disclosures
// -------------------------------------------------------------------------------------------------

func (f *Fingerprinter) probeKnownEndpoints(ctx context.Context, targetURL string, res map[string]*ComponentFinding) {
	baseParsed, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	// Juice Shop application version API: /rest/admin/application-version
	juiceShopVerURL := fmt.Sprintf("%s://%s/rest/admin/application-version", baseParsed.Scheme, baseParsed.Host)
	if f.isOriginAllowed(juiceShopVerURL) {
		reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, juiceShopVerURL, nil)
		if resp, err := f.client.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var data struct {
					Version string `json:"version"`
				}
				if json.NewDecoder(resp.Body).Decode(&data) == nil && data.Version != "" {
					f.mergeComponent(res, ComponentFinding{
						ComponentName: "OWASP Juice Shop",
						Vendor:        "owasp",
						Product:       "juice-shop",
						Version:       data.Version,
						Part:          "a",
						Confidence:    ConfidenceConfirmed,
						Sources:       []DetectionSource{SourceAPI},
						Evidence:      []string{fmt.Sprintf("API disclosure at %s: version %s", juiceShopVerURL, data.Version)},
					})
				}
			}
		}
	}

	// DVGA about page for version extraction: /about
	dvgaAboutURL := fmt.Sprintf("%s://%s/about", baseParsed.Scheme, baseParsed.Host)
	if f.isOriginAllowed(dvgaAboutURL) {
		reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, dvgaAboutURL, nil)
		if resp, err := f.client.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				aboutBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
				f.fingerprintRawHTML(targetURL, string(aboutBytes), res)
			}
		}
	}
}

// -------------------------------------------------------------------------------------------------
// Deduplication, Normalization & Security Controls
// -------------------------------------------------------------------------------------------------

func (f *Fingerprinter) mergeComponent(res map[string]*ComponentFinding, finding ComponentFinding) {
	if finding.Vendor == "" || finding.Product == "" {
		return
	}

	key := fmt.Sprintf("%s:%s", finding.Vendor, finding.Product)
	existing, ok := res[key]
	if !ok {
		// New component
		if finding.Part == "" {
			finding.Part = "a"
		}
		if finding.Confidence == "" {
			finding.Confidence = ConfidenceConfirmedNoVer
			if finding.Version != "" && finding.Version != "*" {
				finding.Confidence = ConfidenceConfirmed
			}
		}
		finding.CPE23 = FormatCPE23(finding.Part, finding.Vendor, finding.Product, finding.Version)
		res[key] = &finding
		return
	}

	// Merge sources
	for _, s := range finding.Sources {
		found := false
		for _, es := range existing.Sources {
			if es == s {
				found = true
				break
			}
		}
		if !found {
			existing.Sources = append(existing.Sources, s)
		}
	}

	// Merge evidence
	for _, ev := range finding.Evidence {
		found := false
		for _, eev := range existing.Evidence {
			if eev == ev {
				found = true
				break
			}
		}
		if !found {
			existing.Evidence = append(existing.Evidence, ev)
		}
	}

	// Upgrade version if newly discovered version is specific
	if (existing.Version == "" || existing.Version == "*") && finding.Version != "" && finding.Version != "*" {
		existing.Version = finding.Version
		existing.Confidence = ConfidenceConfirmed
		existing.CPE23 = FormatCPE23(existing.Part, existing.Vendor, existing.Product, existing.Version)
	}

	// Preserve asset URL if set
	if existing.AssetURL == "" && finding.AssetURL != "" {
		existing.AssetURL = finding.AssetURL
	}
}

func (f *Fingerprinter) buildResult(targetURL string, res map[string]*ComponentFinding) *FingerprintResult {
	result := &FingerprintResult{
		TargetURL:  targetURL,
		Components: make([]ComponentFinding, 0, len(res)),
	}

	for _, comp := range res {
		result.Components = append(result.Components, *comp)
		result.IdentifiedCount++
		if comp.Version != "" && comp.Version != "*" {
			result.ConfirmedVersionCount++
		}
		if comp.CPE23 != "" {
			result.CPEAssignedCount++
		}
	}

	// Sort deterministically by vendor:product
	sort.Slice(result.Components, func(i, j int) bool {
		ki := fmt.Sprintf("%s:%s", result.Components[i].Vendor, result.Components[i].Product)
		kj := fmt.Sprintf("%s:%s", result.Components[j].Vendor, result.Components[j].Product)
		return ki < kj
	})

	return result
}

func (f *Fingerprinter) validateScopeAndSSRF(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("prohibited scheme: %s", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return errors.New("missing host")
	}

	// Check origin scope restriction if enabled
	if len(f.allowedOrigins) > 0 {
		origin := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		if !f.allowedOrigins[origin] {
			return fmt.Errorf("target origin %s not in allowed scope", origin)
		}
	}

	// SSRF IP checks
	ip := net.ParseIP(host)
	if ip != nil {
		prohibited, reason := crawler.ProhibitedIPReason(ip, true, true)
		if prohibited {
			return fmt.Errorf("SSRF refusal: %s", reason)
		}
	}

	return nil
}

func (f *Fingerprinter) isOriginAllowed(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return f.validateScopeAndSSRF(u) == nil
}

func resolveURL(base *url.URL, ref string) string {
	refParsed, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(refParsed)
	return resolved.String()
}

func normalizeOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host), nil
}
