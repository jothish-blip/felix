package fuzzer

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRCE_DefaultProbesIntegrity(t *testing.T) {
	if len(DefaultRCEProbes) == 0 {
		t.Fatal("DefaultRCEProbes slice cannot be empty")
	}

	for i, probe := range DefaultRCEProbes {
		if probe.Name == "" {
			t.Errorf("Probe %d has empty Name", i)
		}
		if probe.Payload == "" {
			t.Errorf("Probe %s has empty Payload", probe.Name)
		}
		if probe.ArithmeticToken == "" {
			t.Errorf("Probe %s has empty ArithmeticToken", probe.Name)
		}
		if probe.Type == RCENone {
			t.Errorf("Probe %s has invalid type RCENone", probe.Name)
		}
	}
}

func TestRCE_CommandSeparatorsExecution(t *testing.T) {
	// Mock vulnerable shell execution endpoint: ping -c 1 <ip>
	// When ; expr 41 + 1 is passed, the shell runs expr and outputs 42
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		w.Header().Set("Content-Type", "text/plain")
		if strings.Contains(ip, "expr 41 + 1") || strings.Contains(ip, "echo $((41+1))") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "PING 127.0.0.1 (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.035 ms\n42\n")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "PING %s (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.035 ms\n", ip)
	}))
	defer server.Close()

	pe := NewParameterExtractor()
	analyzer := NewRCEAnalyzer(server.Client(), pe)

	req, err := http.NewRequest(http.MethodGet, server.URL+"?ip=127.0.0.1", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	findings, err := analyzer.AnalyzeRequest(req)
	if err != nil {
		t.Fatalf("AnalyzeRequest returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Expected at least one confirmed RCE finding for command separator, got 0")
	}

	foundConfirmed := false
	for _, f := range findings {
		if f.Confidence == RCEConfidenceConfirmed && f.Type == RCECommandInjection && f.ArithmeticToken == "42" {
			foundConfirmed = true
			if !f.NonTargetPreserved {
				t.Errorf("Expected NonTargetPreserved=true")
			}
			break
		}
	}

	if !foundConfirmed {
		t.Fatalf("Did not find confirmed RCE finding with token 42: %+v", findings)
	}
}

func TestRCE_StaticReflectionRejected(t *testing.T) {
	// Mock defended endpoint: reflects input into an HTML form input tag without shell execution
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("search")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<html><body><form><input type="text" name="search" value="%s"></form></body></html>`, query)
	}))
	defer server.Close()

	pe := NewParameterExtractor()
	analyzer := NewRCEAnalyzer(server.Client(), pe)

	req, err := http.NewRequest(http.MethodGet, server.URL+"?search=test", nil)
	if err != nil {
		t.Fatalf("Failed to construct request: %v", err)
	}

	findings, err := analyzer.AnalyzeRequest(req)
	if err != nil {
		t.Fatalf("AnalyzeRequest error: %v", err)
	}

	for _, f := range findings {
		if f.Confidence == RCEConfidenceConfirmed {
			t.Fatalf("False positive: static raw reflection of formula was incorrectly marked CONFIRMED: %+v", f)
		}
	}
}

func TestRCE_StaticBaselineIgnored(t *testing.T) {
	// Mock endpoint whose baseline naturally contains "42" (e.g. copyright 2042 or address 42)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<html><body><h1>Store 42</h1><p>Items in stock: 42</p></body></html>`)
	}))
	defer server.Close()

	pe := NewParameterExtractor()
	analyzer := NewRCEAnalyzer(server.Client(), pe)

	req, err := http.NewRequest(http.MethodGet, server.URL+"?item=book", nil)
	if err != nil {
		t.Fatalf("Failed to construct request: %v", err)
	}

	findings, err := analyzer.AnalyzeRequest(req)
	if err != nil {
		t.Fatalf("AnalyzeRequest error: %v", err)
	}

	for _, f := range findings {
		if f.Confidence == RCEConfidenceConfirmed {
			t.Fatalf("False positive: baseline containing 42 triggered confirmed RCE: %+v", f)
		}
	}
}

func TestRCE_SSJI_ArithmeticEvaluation(t *testing.T) {
	// Mock Node.js eval() endpoint: receives code, executes eval(), and returns calculated output
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("calc")
		w.Header().Set("Content-Type", "text/plain")
		if strings.Contains(code, "41+1") || strings.Contains(code, "41 + 1") || strings.Contains(code, "21 + 21") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "Calculation result: 42")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Calculation result: %s", code)
	}))
	defer server.Close()

	pe := NewParameterExtractor()
	analyzer := NewRCEAnalyzer(server.Client(), pe)

	req, err := http.NewRequest(http.MethodGet, server.URL+"?calc=10%2B10", nil)
	if err != nil {
		t.Fatalf("Failed to construct request: %v", err)
	}

	findings, err := analyzer.AnalyzeRequest(req)
	if err != nil {
		t.Fatalf("AnalyzeRequest error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Expected confirmed SSJI finding, got 0")
	}

	foundConfirmed := false
	for _, f := range findings {
		if f.Confidence == RCEConfidenceConfirmed && f.ArithmeticToken == "42" {
			foundConfirmed = true
			break
		}
	}

	if !foundConfirmed {
		t.Fatalf("Failed to confirm SSJI finding: %+v", findings)
	}
}

func TestRCE_NonTargetParameterPreservation(t *testing.T) {
	var observedRequests []url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		vals := url.Values{}
		for k, v := range r.Form {
			vals[k] = append([]string(nil), v...)
		}
		observedRequests = append(observedRequests, vals)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	pe := NewParameterExtractor()
	analyzer := NewRCEAnalyzer(server.Client(), pe)

	form := url.Values{
		"session_token": []string{"sec_99182"},
		"cmd":           []string{"status"},
		"user_id":       []string{"usr_admin"},
	}

	req, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("Failed to construct POST: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	params, err := pe.Extract(req)
	if err != nil {
		t.Fatalf("Extract error: %v", err)
	}

	var cmdParam *Parameter
	for _, p := range params {
		if p.Name == "cmd" {
			cmdParam = &p
			break
		}
	}

	if cmdParam == nil {
		t.Fatal("Could not find cmd parameter")
	}

	_, err = analyzer.AnalyzeParameter(req, *cmdParam)
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	if len(observedRequests) == 0 {
		t.Fatal("No requests observed by mock server")
	}

	for _, formVals := range observedRequests {
		if formVals.Get("session_token") != "sec_99182" {
			t.Errorf("session_token was modified: %s", formVals.Get("session_token"))
		}
		if formVals.Get("user_id") != "usr_admin" {
			t.Errorf("user_id was modified: %s", formVals.Get("user_id"))
		}
	}
}
