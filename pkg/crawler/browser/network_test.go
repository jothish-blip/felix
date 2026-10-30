package browser

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

func TestIsProhibitedURL(t *testing.T) {
	tests := []struct {
		name          string
		targetURL     string
		allowLoopback bool
		allowPrivate  bool
		wantBlocked   bool
	}{
		// Cloud Metadata
		{"AWS Metadata IPv4", "http://169.254.169.254/latest/meta-data/", true, true, true},
		{"AWS Metadata IPv6", "http://[fd00:ec2::254]/latest/meta-data/", true, true, true},
		{"GCP Metadata Hostname", "http://metadata.google.internal/computeMetadata/v1/", true, true, true},
		{"Instance Data Hostname", "http://instance-data/latest/meta-data/", true, true, true},

		// Loopback
		{"Loopback IPv4 Blocked", "http://127.0.0.1:8080/admin", false, false, true},
		{"Loopback IPv4 Allowed", "http://127.0.0.1:8080/admin", true, false, false},
		{"Loopback Hostname Blocked", "http://localhost:3000/", false, false, true},
		{"Loopback Hostname Allowed", "http://localhost:3000/", true, false, false},
		{"Loopback Octet Blocked", "http://127.0.0.2:80/", false, false, true},

		// RFC 1918 Private Ranges
		{"10.0.0.0/8 Blocked", "http://10.1.2.3/api", false, false, true},
		{"10.0.0.0/8 Allowed", "http://10.1.2.3/api", false, true, false},
		{"172.16.0.0/12 Blocked", "http://172.16.5.6:8080/", false, false, true},
		{"172.16.0.0/12 Allowed", "http://172.16.5.6:8080/", false, true, false},
		{"192.168.0.0/16 Blocked", "http://192.168.1.1/router", false, false, true},
		{"192.168.0.0/16 Allowed", "http://192.168.1.1/router", false, true, false},

		// Non-Routable & Link-Local
		{"Zero Network Blocked", "http://0.0.0.0/", true, true, true},
		{"Link-Local Blocked", "http://169.254.1.1/service", true, true, true},
		{"IPv6 Link-Local Blocked", "http://[fe80::1]/", true, true, true},
		{"IPv6 ULA Blocked", "http://[fc00::1]/", false, false, true},
		{"IPv6 Loopback Blocked", "http://[::1]/", false, false, true},

		// IPv4-Mapped IPv6 & Alternate Encodings
		{"IPv4-Mapped IPv6 Loopback", "http://[::ffff:127.0.0.1]/", false, false, true},
		{"IPv4-Mapped IPv6 Cloud Metadata", "http://[::ffff:169.254.169.254]/", true, true, true},
		{"IPv4-Mapped IPv6 RFC 1918 Blocked", "http://[::ffff:10.1.2.3]/", false, false, true},
		{"IPv4-Mapped IPv6 RFC 1918 Allowed", "http://[::ffff:10.1.2.3]/", false, true, false},
		{"Dword Decimal IP Loopback (2130706433)", "http://2130706433/", false, false, true},
		{"Hex IP Loopback (0x7f000001)", "http://0x7f000001/", false, false, true},

		// Legitimate Public Targets
		{"Public Domain", "https://example.com/login", false, false, false},
		{"Public OWASP Target", "https://demo.owasp-juice.shop/api/Challenges", false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := IsProhibitedURL(tt.targetURL, tt.allowLoopback, tt.allowPrivate)
			if blocked != tt.wantBlocked {
				t.Errorf("IsProhibitedURL(%q, %v, %v) = %v (reason: %s); want %v",
					tt.targetURL, tt.allowLoopback, tt.allowPrivate, blocked, reason, tt.wantBlocked)
			}
		})
	}
}

func TestRedactHeaders(t *testing.T) {
	raw := map[string]string{
		"Authorization":   "Bearer secret_jwt_token_12345",
		"Cookie":          "sessionid=xyz987; tracker=abc",
		"X-Api-Key":       "prod_live_key_555",
		"Content-Type":    "application/json",
		"Accept-Language": "en-US",
	}

	redacted := RedactHeaders(raw)
	if redacted["Authorization"] != "[REDACTED_BY_SECURITY_POLICY]" {
		t.Errorf("Authorization header not redacted: %s", redacted["Authorization"])
	}
	if redacted["Cookie"] != "[REDACTED_BY_SECURITY_POLICY]" {
		t.Errorf("Cookie header not redacted: %s", redacted["Cookie"])
	}
	if redacted["X-Api-Key"] != "[REDACTED_BY_SECURITY_POLICY]" {
		t.Errorf("X-Api-Key header not redacted: %s", redacted["X-Api-Key"])
	}
	if redacted["Content-Type"] != "application/json" {
		t.Errorf("Harmless Content-Type header modified: %s", redacted["Content-Type"])
	}
	if redacted["Accept-Language"] != "en-US" {
		t.Errorf("Harmless Accept-Language header modified: %s", redacted["Accept-Language"])
	}
}

func TestSafeDialerInterception(t *testing.T) {
	// 1. Launch a local test HTTP server to simulate target SPA application
	var safeHitCount int32
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to bind local listener: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>FELIX SafeDialer Verification Page</title></head>
<body>
<h1>FELIX SSRF & CDP Network Gateway Test</h1>
<div id="status">pending</div>
<script>
  (async function() {
    // 1. Dispatch safe API request with POST JSON payload
    try {
      const resp = await fetch('/api/safe-data', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Felix-Audit': 'v3-alpha' },
        body: JSON.stringify({ audit_id: "sec-9901", role: "crawler" })
      });
      const data = await resp.json();
      console.log("Safe API Response:", data);
    } catch(err) {
      console.error("Safe API Error:", err);
    }

    // 2. Dispatch prohibited cloud metadata SSRF probe
    try {
      await fetch('http://169.254.169.254/latest/meta-data/');
    } catch(err) {
      console.log("SSRF fetch successfully blocked by client policy:", err);
    }

    // Mark completion in DOM for test synchronization
    document.getElementById('status').innerText = 'completed';
  })();
</script>
</body>
</html>`))
	})

	mux.HandleFunc("/api/safe-data", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&safeHitCount, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success","message":"safe endpoint reachable","items":[1,2,3]}`))
	})

	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	testPageURL := fmt.Sprintf("http://%s/", serverAddr)

	// 2. Launch Headless Browser Session
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	cfg := DefaultConfig()
	inst, err := Launch(ctx, cfg)
	if err != nil {
		t.Fatalf("Failed to launch browser: %v", err)
	}
	defer inst.Close()

	// 3. Attach SafeDialer Gateway with loopback blocked EXCEPT for the explicit test server host
	gw, err := AttachNetworkGateway(ctx, inst, GatewayOptions{
		AllowLoopback:   false,
		AllowPrivateIPs: false,
		AllowedHosts:    []string{serverAddr},
	})
	if err != nil {
		t.Fatalf("Failed to attach network gateway: %v", err)
	}
	defer gw.Stop()

	// 4. Navigate to test page and wait for JS execution to complete
	err = chromedp.Do(inst.Ctx,
		chromedp.Navigate(testPageURL),
		chromedp.WaitVisible("#status"),
	)
	if err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// Wait up to 3 seconds for async fetches to settle
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&safeHitCount) > 0 && len(gw.GetBlockedRequests()) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// 5. Verify Safe Endpoint Request & Response
	if atomic.LoadInt32(&safeHitCount) == 0 {
		t.Errorf("Expected /api/safe-data to hit server, but server received 0 hits")
	}

	reqs := gw.GetRequests()
	var safeReq *InterceptedRequest
	for _, r := range reqs {
		if strings.Contains(r.URL, "/api/safe-data") {
			safeReq = r
			break
		}
	}
	if safeReq == nil {
		t.Fatalf("Expected /api/safe-data in captured requests, got %d requests", len(reqs))
	}
	if safeReq.Method != "POST" {
		t.Errorf("Expected safe request method POST, got %s", safeReq.Method)
	}
	if !strings.Contains(safeReq.PostData, "sec-9901") {
		t.Errorf("Expected POST data to contain 'sec-9901', got: %s", safeReq.PostData)
	}
	if safeReq.Headers["X-Felix-Audit"] != "v3-alpha" && safeReq.Headers["x-felix-audit"] != "v3-alpha" {
		t.Logf("Note: Headers captured: %v", safeReq.Headers)
	}

	resps := gw.GetResponses()
	var safeResp *InterceptedResponse
	for _, r := range resps {
		if strings.Contains(r.URL, "/api/safe-data") {
			safeResp = r
			break
		}
	}
	if safeResp == nil {
		t.Fatalf("Expected /api/safe-data in captured responses, got %d responses", len(resps))
	}
	if safeResp.Status != 200 {
		t.Errorf("Expected HTTP 200 for safe-data, got %d", safeResp.Status)
	}

	// 6. Verify Prohibited SSRF Cloud Metadata Block
	blockedReqs := gw.GetBlockedRequests()
	if len(blockedReqs) == 0 {
		t.Fatalf("Expected at least 1 blocked request, got 0")
	}

	var metadataBlocked *InterceptedRequest
	for _, b := range blockedReqs {
		if strings.Contains(b.URL, "169.254.169.254") {
			metadataBlocked = b
			break
		}
	}

	if metadataBlocked == nil {
		t.Fatalf("Expected 169.254.169.254 to be blocked, but blocked list contained: %v", blockedReqs)
	}
	if !metadataBlocked.Blocked {
		t.Errorf("Expected metadataBlocked.Blocked to be true")
	}
	t.Logf("Successfully blocked prohibited SSRF attempt: URL=%s Reason=%q",
		metadataBlocked.URL, metadataBlocked.BlockReason)

	// 7. Verify Dynamic API Route Catalog
	routes := gw.GetAPIRoutes()
	foundRoute := false
	for _, r := range routes {
		if strings.Contains(r, "/api/safe-data") {
			foundRoute = true
			break
		}
	}
	if !foundRoute {
		t.Errorf("Expected /api/safe-data in API routes catalog, got: %v", routes)
	}

	t.Logf("Interception Verification Succeeded: %d requests, %d responses, %d blocked, %d API routes discovered",
		len(reqs), len(resps), len(blockedReqs), len(routes))
}

func TestJuiceShopDynamicRouteSniffer(t *testing.T) {
	juiceRoutes := []string{
		"/api/Challenges",
		"/rest/products/search?q=",
		"/rest/user/whoami",
		"/api/BasketItems",
		"/api/Quantitys",
		"/rest/deluxe-membership/price",
		"/api/Complaints",
		"/api/Feedbacks",
		"/rest/saveLoginIp",
		"/rest/image-captchas",
		"/api/Cards",
		"/api/Addresss",
		"/api/DeliveryMethods",
		"/rest/wallet/balance",
		"/rest/languages",
		"/rest/memories",
	}

	var hitCount int32
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to bind listener: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>OWASP Juice Shop Simulated SPA</title></head>
<body>
<h1>Juice Shop Catalog</h1>
<div id="status">pending</div>
<script>
  (async function() {
    const endpoints = [
      '/api/Challenges',
      '/rest/products/search?q=',
      '/rest/user/whoami',
      '/api/BasketItems',
      '/api/Quantitys',
      '/rest/deluxe-membership/price',
      '/api/Complaints',
      '/api/Feedbacks',
      '/rest/saveLoginIp',
      '/rest/image-captchas',
      '/api/Cards',
      '/api/Addresss',
      '/api/DeliveryMethods',
      '/rest/wallet/balance',
      '/rest/languages',
      '/rest/memories'
    ];
    for (const ep of endpoints) {
      fetch(ep).catch(e => console.error(e));
    }
    // Prohibited probes: IMDS & unauthorized loopback port
    fetch('http://169.254.169.254/latest/meta-data/').catch(e => {});
    fetch('http://127.0.0.1:8080/internal-admin').catch(e => {});
    document.getElementById('status').innerText = 'completed';
  })();
</script>
</body>
</html>`))
	})

	for _, ep := range juiceRoutes {
		path := strings.Split(ep, "?")[0]
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&hitCount, 1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		})
	}

	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	cfg := DefaultConfig()
	inst, err := Launch(ctx, cfg)
	if err != nil {
		t.Fatalf("Failed to launch browser: %v", err)
	}
	defer inst.Close()

	gw, err := AttachNetworkGateway(ctx, inst, GatewayOptions{
		AllowLoopback:   false,
		AllowPrivateIPs: false,
		AllowedHosts:    []string{serverAddr},
	})
	if err != nil {
		t.Fatalf("Failed to attach network gateway: %v", err)
	}
	defer gw.Stop()

	testURL := fmt.Sprintf("http://%s/", serverAddr)
	err = chromedp.Do(inst.Ctx,
		chromedp.Navigate(testURL),
		chromedp.WaitVisible("#status"),
	)
	if err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&hitCount) >= int32(len(juiceRoutes)) && len(gw.GetBlockedRequests()) >= 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	blocked := gw.GetBlockedRequests()
	if len(blocked) < 2 {
		t.Fatalf("Expected at least 2 blocked requests (IMDS + loopback), got %d: %v", len(blocked), blocked)
	}

	routes := gw.GetAPIRoutes()
	if len(routes) < 15 {
		t.Fatalf("Expected dynamic route capture delta >= 15, got %d routes: %v", len(routes), routes)
	}

	t.Logf("Juice Shop Verification PASSED: Discovered %d dynamic API routes (threshold >= 15 met); Blocked %d SSRF attempts (zero bypasses)",
		len(routes), len(blocked))
}
