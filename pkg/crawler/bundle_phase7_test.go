package crawler_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"felix/pkg/crawler"
)

func TestPhase7_JSLexerRegexLiteralAndAngularRestExtraction(t *testing.T) {
	// Contains regex literals with quotes (' and ") plus Angular this.http calls & template literals
	angularBundle := `
		var cleanQuoteRegex = /['"\\]/g;
		var apiMatch = /\/rest\/items\/(\d+)/i;
		function ProductService(http, hostServer) {
			this.http = http;
			this.hostServer = hostServer;
			this.search = function(q) {
				return this.http.get(this.hostServer + "/rest/products/search");
			};
			this.login = function(body) {
				return this.http.post(` + "`${this.host}/rest/user/login`" + `, body);
			};
			this.basket = function(id) {
				return this.http.get(` + "`/rest/basket/${id}`" + `);
			};
		}
		var notARoute = "hello/world/string";
	`

	opts := crawler.DefaultBundleAnalysisOptions()
	opts.TargetHost = "juice.local"
	extractor := crawler.NewBundleExtractor(opts)

	cands, _, _, warnings := extractor.ExtractFromBundle([]byte(angularBundle), "http://juice.local/main.js")
	for _, w := range warnings {
		if strings.Contains(w, "Unterminated string literal") {
			t.Fatalf("unexpected unterminated string warning from regex literal: %v", warnings)
		}
	}

	gotPaths := make(map[string]string)
	for _, c := range cands {
		gotPaths[c.Path] = c.HTTPMethod
		if strings.Contains(c.Path, "hello/world") {
			t.Fatalf("non-API string leaked into candidates: %+v", c)
		}
	}

	for _, expected := range []string{"/rest/products/search", "/rest/user/login", "/rest/basket/{param}"} {
		if _, ok := gotPaths[expected]; !ok {
			t.Fatalf("expected Angular REST route %q in candidates, got: %+v", expected, gotPaths)
		}
	}
}

func TestPhase7_WebpackIIFEAndRelativeObjectMapExtraction(t *testing.T) {
	crapiLikeBundle := `(self.webpackChunkcrapi=self.webpackChunkcrapi||[]).push([[179],function(e,t,n){
		const og = "identity/";
		const sg = {
			LOGIN: "api/auth/login",
			VEHICLES: "api/v2/vehicle/vehicles",
			SIGNUP: "api/auth/signup"
		};
		function run() {
			n.post(og + sg.LOGIN);
			n.get(og + sg.VEHICLES);
			fetch("workshop/api/shop/products");
			axios.get("community/api/v2/community/posts/recent");
		}
		return sg;
	}]);`

	opts := crawler.DefaultBundleAnalysisOptions()
	opts.TargetHost = "crapi.local"
	extractor := crawler.NewBundleExtractor(opts)

	cands, _, _, warnings := extractor.ExtractFromBundle([]byte(crapiLikeBundle), "http://crapi.local/static/js/main.chunk.js")
	if len(warnings) > 0 {
		t.Fatalf("unexpected bundle warnings: %v", warnings)
	}

	got := make(map[string]bool)
	for _, c := range cands {
		got[c.Path] = true
	}

	for _, want := range []string{
		"/identity/api/auth/login",
		"/identity/api/v2/vehicle/vehicles",
		"/workshop/api/shop/products",
		"/community/api/v2/community/posts/recent",
	} {
		if !got[want] {
			t.Fatalf("expected crAPI route %q in extracted candidates, got %v", want, got)
		}
	}
}

func TestPhase7_MultiIdentitySummaryDeduplicatesAcrossIdentities(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><script src="/main.js"></script></html>`))
		case "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`fetch("/rest/products/search");`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	opts := crawler.DefaultActiveCrawlOptions(srv.URL)
	opts.AllowLoopback = true
	opts.MaxDepth = 2
	opts.MaxPages = 10
	opts.Timeout = 2 * time.Second

	c1 := srv.Client()
	c2 := srv.Client()
	multi, err := crawler.CrawlMultiIdentity(t.Context(), opts, map[string]*http.Client{
		"ANONYMOUS": c1,
		"USER_A":    c2,
	})
	if err != nil {
		t.Fatalf("CrawlMultiIdentity failed: %v", err)
	}

	if multi.Summary.TotalJavaScriptBundles != 1 {
		t.Fatalf("expected deduplicated TotalJavaScriptBundles=1 across 2 identities, got %d", multi.Summary.TotalJavaScriptBundles)
	}
	if multi.Summary.TotalEndpointCandidates != 1 {
		t.Fatalf("expected deduplicated TotalEndpointCandidates=1 across 2 identities, got %d", multi.Summary.TotalEndpointCandidates)
	}
}
