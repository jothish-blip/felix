package fuzzer

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSSTI_DefaultProbesIntegrity(t *testing.T) {
	if len(DefaultSSTIProbes) == 0 {
		t.Fatal("DefaultSSTIProbes slice cannot be empty")
	}

	for i, probe := range DefaultSSTIProbes {
		if probe.Name == "" {
			t.Errorf("Probe %d has empty Name", i)
		}
		if probe.Payload == "" {
			t.Errorf("Probe %s has empty Payload", probe.Name)
		}
		if probe.ArithmeticToken == "" {
			t.Errorf("Probe %s has empty ArithmeticToken", probe.Name)
		}
		if probe.Type == SSTINone {
			t.Errorf("Probe %s has invalid type SSTINone", probe.Name)
		}
	}
}

func TestSSTI_Jinja2TwigArithmeticEvaluation(t *testing.T) {
	// Mock server evaluating Jinja2 expressions
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "text/html")
		if strings.Contains(name, "{{7*7}}") || strings.Contains(name, "{{ 7*7 }}") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html><body><h1>Welcome</h1><div>Result: 49</div></body></html>")
			return
		}
		if strings.Contains(name, "{{7*'7'}}") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html><body><h1>Welcome</h1><div>Result: 7777777</div></body></html>")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body><h1>Welcome</h1><div>User: %s</div></body></html>", name)
	}))
	defer server.Close()

	pe := NewParameterExtractor()
	analyzer := NewSSTIAnalyzer(server.Client(), pe)

	req, err := http.NewRequest(http.MethodGet, server.URL+"?name=Guest", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	findings, err := analyzer.AnalyzeRequest(req)
	if err != nil {
		t.Fatalf("AnalyzeRequest error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Expected confirmed SSTI finding for Jinja2, got 0")
	}

	foundConfirmed := false
	for _, f := range findings {
		if f.Confidence == SSTIConfidenceConfirmed && f.Type == SSTIJinja2Twig && f.ArithmeticToken == "49" {
			foundConfirmed = true
			if !f.NonTargetPreserved {
				t.Errorf("Expected NonTargetPreserved=true")
			}
			break
		}
	}

	if !foundConfirmed {
		t.Fatalf("Did not find confirmed SSTI finding: %+v", findings)
	}
}

func TestSSTI_FreemarkerEvaluation(t *testing.T) {
	// Mock server evaluating Freemarker ${7*7}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tmpl := r.URL.Query().Get("template")
		w.Header().Set("Content-Type", "text/html")
		if strings.Contains(tmpl, "${7*7}") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html><body><h1>Report</h1><span class='total'>49</span></body></html>")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body><h1>Report</h1><span class='total'>%s</span></body></html>", tmpl)
	}))
	defer server.Close()

	pe := NewParameterExtractor()
	analyzer := NewSSTIAnalyzer(server.Client(), pe)

	req, err := http.NewRequest(http.MethodGet, server.URL+"?template=default", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	findings, err := analyzer.AnalyzeRequest(req)
	if err != nil {
		t.Fatalf("AnalyzeRequest error: %v", err)
	}

	foundConfirmed := false
	for _, f := range findings {
		if f.Confidence == SSTIConfidenceConfirmed && f.Type == SSTIFreemarker && f.ArithmeticToken == "49" {
			foundConfirmed = true
			break
		}
	}

	if !foundConfirmed {
		t.Fatalf("Did not find confirmed Freemarker SSTI finding: %+v", findings)
	}
}

func TestSSTI_RubyERBEvaluation(t *testing.T) {
	// Mock server evaluating Ruby ERB <%= 7*7 %>
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		view := r.URL.Query().Get("view")
		w.Header().Set("Content-Type", "text/html")
		if strings.Contains(view, "<%= 7*7 %>") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html><body><div>Rendered: 49</div></body></html>")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body><div>Rendered: %s</div></body></html>", view)
	}))
	defer server.Close()

	pe := NewParameterExtractor()
	analyzer := NewSSTIAnalyzer(server.Client(), pe)

	req, err := http.NewRequest(http.MethodGet, server.URL+"?view=index", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	findings, err := analyzer.AnalyzeRequest(req)
	if err != nil {
		t.Fatalf("AnalyzeRequest error: %v", err)
	}

	foundConfirmed := false
	for _, f := range findings {
		if f.Confidence == SSTIConfidenceConfirmed && f.Type == SSTIErb && f.ArithmeticToken == "49" {
			foundConfirmed = true
			break
		}
	}

	if !foundConfirmed {
		t.Fatalf("Did not find confirmed Ruby ERB SSTI finding: %+v", findings)
	}
}

func TestSSTI_StaticReflectionRejected(t *testing.T) {
	// Mock defended endpoint: reflects input into an HTML tag or text without template evaluation
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Statically echoes the raw string
		fmt.Fprintf(w, `<html><body><h1>Search</h1><p>You searched for: %s</p></body></html>`, q)
	}))
	defer server.Close()

	pe := NewParameterExtractor()
	analyzer := NewSSTIAnalyzer(server.Client(), pe)

	req, err := http.NewRequest(http.MethodGet, server.URL+"?q=test", nil)
	if err != nil {
		t.Fatalf("Failed to construct request: %v", err)
	}

	findings, err := analyzer.AnalyzeRequest(req)
	if err != nil {
		t.Fatalf("AnalyzeRequest error: %v", err)
	}

	for _, f := range findings {
		if f.Confidence == SSTIConfidenceConfirmed {
			t.Fatalf("False positive: static raw reflection of template expression was marked CONFIRMED: %+v", f)
		}
	}
}

func TestSSTI_BaselineIgnored(t *testing.T) {
	// Mock server whose baseline response already includes "49" (e.g. "49ers" or "$49")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><body><h1>Store</h1><p>Price: $49</p></body></html>`)
	}))
	defer server.Close()

	pe := NewParameterExtractor()
	analyzer := NewSSTIAnalyzer(server.Client(), pe)

	req, err := http.NewRequest(http.MethodGet, server.URL+"?product=hat", nil)
	if err != nil {
		t.Fatalf("Failed to construct request: %v", err)
	}

	findings, err := analyzer.AnalyzeRequest(req)
	if err != nil {
		t.Fatalf("AnalyzeRequest error: %v", err)
	}

	for _, f := range findings {
		if f.Confidence == SSTIConfidenceConfirmed {
			t.Fatalf("False positive: baseline containing 49 triggered confirmed SSTI: %+v", f)
		}
	}
}

func TestSSTI_NonTargetParameterPreservation(t *testing.T) {
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
	analyzer := NewSSTIAnalyzer(server.Client(), pe)

	form := url.Values{
		"csrf_token": []string{"csrf_abc123"},
		"tmpl":       []string{"profile"},
		"format":     []string{"html"},
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

	var tmplParam *Parameter
	for _, p := range params {
		if p.Name == "tmpl" {
			tmplParam = &p
			break
		}
	}

	if tmplParam == nil {
		t.Fatal("Could not find tmpl parameter")
	}

	_, err = analyzer.AnalyzeParameter(req, *tmplParam)
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	if len(observedRequests) == 0 {
		t.Fatal("No requests observed by mock server")
	}

	for _, formVals := range observedRequests {
		if formVals.Get("csrf_token") != "csrf_abc123" {
			t.Errorf("csrf_token was modified: %s", formVals.Get("csrf_token"))
		}
		if formVals.Get("format") != "html" {
			t.Errorf("format was modified: %s", formVals.Get("format"))
		}
	}
}
