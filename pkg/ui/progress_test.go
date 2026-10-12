package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestProgressOutput(t *testing.T) {
	var buf bytes.Buffer
	p := New(Options{
		Writer:   &buf,
		Quiet:    false,
		JSONMode: false,
	})

	p.Step("Connecting to %s", "https://example.com")
	p.Success("Discovered %d assets", 15)
	p.Warn("Slow response detected")
	p.Error("Asset 404: %s", "/missing.js")

	output := buf.String()
	if !strings.Contains(output, "[*] Connecting to https://example.com\n") {
		t.Errorf("expected step output, got:\n%s", output)
	}
	if !strings.Contains(output, "[+] Discovered 15 assets\n") {
		t.Errorf("expected success output, got:\n%s", output)
	}
	if !strings.Contains(output, "[!] Slow response detected\n") {
		t.Errorf("expected warning output, got:\n%s", output)
	}
	if !strings.Contains(output, "[-] Asset 404: /missing.js\n") {
		t.Errorf("expected error output, got:\n%s", output)
	}

	cb := p.Callback()
	cb("[*] Custom callback message")
	if !strings.Contains(buf.String(), "[*] Custom callback message\n") {
		t.Errorf("expected callback message in output, got:\n%s", buf.String())
	}
}

func TestProgressQuietAndJSONMode(t *testing.T) {
	var bufQuiet bytes.Buffer
	pq := New(Options{
		Writer:   &bufQuiet,
		Quiet:    true,
		JSONMode: false,
	})
	pq.Step("Should not appear")
	pq.Success("Should not appear")
	pq.Warn("Should not appear")
	pq.Error("Should not appear")
	pq.Callback()("Should not appear")

	if bufQuiet.Len() != 0 {
		t.Errorf("expected empty output in quiet mode, got: %q", bufQuiet.String())
	}

	var bufJSON bytes.Buffer
	pj := New(Options{
		Writer:   &bufJSON,
		Quiet:    false,
		JSONMode: true,
	})
	pj.Step("Should not appear")
	pj.Success("Should not appear")
	pj.Warn("Should not appear")
	pj.Error("Should not appear")
	pj.Callback()("Should not appear")

	if bufJSON.Len() != 0 {
		t.Errorf("expected empty output in JSON mode, got: %q", bufJSON.String())
	}
}
