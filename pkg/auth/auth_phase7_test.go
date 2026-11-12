package auth

import (
	"net/http"
	"testing"

	"felix/pkg/discovery"
	"felix/pkg/report"
)

func TestPhase7_CookieObservationsAreNotPromotedToConfirmed(t *testing.T) {
	eng := NewEngine()
	hdr := http.Header{}
	hdr.Add("Set-Cookie", "sessionid=abc12345; HttpOnly; Path=/")

	_, findings := eng.AnalyzeAuthentication(&discovery.Inventory{}, nil, hdr, "http://127.0.0.1:5000", "asm", "exec", "tgt")
	if len(findings) == 0 {
		t.Fatalf("expected HTTP cookie observation findings")
	}
	for _, f := range findings {
		if f.Verification.Status == report.VerificationObserved && f.Status == report.FindingStatusConfirmed {
			t.Fatalf("observed cookie finding %q must not have status CONFIRMED", f.Title)
		}
	}
}

func TestPhase7_BuildMissingAuthFindingUnconfirmedStaysSuspected(t *testing.T) {
	fUnconf := buildMissingAuthFinding("http://127.0.0.1:5000/api/private", 200, false)
	if fUnconf.Status != report.FindingStatusSuspected {
		t.Fatalf("expected SUSPECTED when confirmed=false, got %s", fUnconf.Status)
	}
	if fUnconf.ClassificationOutcome != report.OutcomeSuspected {
		t.Fatalf("expected OutcomeSuspected when confirmed=false, got %s", fUnconf.ClassificationOutcome)
	}

	fConf := buildMissingAuthFinding("http://127.0.0.1:5000/api/private", 200, true)
	if fConf.Status != report.FindingStatusConfirmed || fConf.ClassificationOutcome != report.OutcomeConfirmed {
		t.Fatalf("expected CONFIRMED when confirmed=true, got (%s, %s)", fConf.Status, fConf.ClassificationOutcome)
	}
}
