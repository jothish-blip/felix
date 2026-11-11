package investigation

import (
	"net/http"
	"strings"
	"testing"

	"felix/pkg/report"
)

func TestPhase5_AnalyzeAttackChains_RejectsPlaceholderAndUnvalidatedLinks(t *testing.T) {
	// 1. Placeholder AWS key AKIAIOSFODNN7EXAMPLE must NEVER form chain_cred_to_bola
	placeholderSecret := &InvestigatedFinding{
		Finding: report.Finding{
			ID:       "F-INV-PH",
			Title:    "Exposed AWS Access Key",
			Category: "secrets",
			Target:   "http://127.0.0.1:8080/docs.js",
			Endpoint: "/docs.js",
			Evidence: `API_KEY = "AKIAIOSFODNN7EXAMPLE"`,
			EvidenceDetails: report.EvidenceDetails{
				Details: map[string]string{
					"is_placeholder":    "true",
					"credential_status": "INVALID",
				},
			},
		},
		ValidationStatus: StatusConfirmed,
	}
	bola := &InvestigatedFinding{
		Finding: report.Finding{
			ID:       "F-INV-BOLA",
			Title:    "BOLA Object Read",
			Category: "BOLA",
			Target:   "http://127.0.0.1:8080/api/orders/1",
			Endpoint: "/api/orders/1",
		},
		ValidationStatus: StatusConfirmed,
	}

	chains := AnalyzeAttackChains([]*InvestigatedFinding{placeholderSecret, bola})
	for _, c := range chains {
		if c.ID == "chain_cred_to_bola" {
			t.Fatalf("placeholder credential MUST NOT generate chain_cred_to_bola: %+v", c)
		}
	}

	// 2. Real non-placeholder credential on different host MUST NOT connect to BOLA on another host
	crossOriginSecret := &InvestigatedFinding{
		Finding: report.Finding{
			ID:       "F-INV-SEC2",
			Title:    "Exposed Live Token",
			Category: "secrets",
			Target:   "http://127.0.0.1:9999/config.js",
			Endpoint: "/config.js",
			Evidence: `bearer tok_live_real_secret_value_abc123456`,
		},
		ValidationStatus: StatusConfirmed,
	}
	chainsCross := AnalyzeAttackChains([]*InvestigatedFinding{crossOriginSecret, bola})
	for _, c := range chainsCross {
		if c.ID == "chain_cred_to_bola" {
			t.Fatalf("cross-origin secret MUST NOT chain to BOLA on different host: %+v", c)
		}
	}

	// 3. Same-origin non-placeholder secret + BOLA without transition_verified MUST remain POTENTIAL
	sameOriginSecret := &InvestigatedFinding{
		Finding: report.Finding{
			ID:       "F-INV-SEC3",
			Title:    "Exposed Live Token",
			Category: "secrets",
			Target:   "http://127.0.0.1:8080/config.js",
			Endpoint: "/config.js",
			Evidence: `token="tok_live_real_secret_value_abc123456"`,
		},
		ValidationStatus: StatusConfirmed,
	}
	chainsSame := AnalyzeAttackChains([]*InvestigatedFinding{sameOriginSecret, bola})
	if len(chainsSame) != 1 || chainsSame[0].ID != "chain_cred_to_bola" {
		t.Fatalf("expected 1 candidate chain_cred_to_bola on same origin, got %+v", chainsSame)
	}
	if chainsSame[0].Status != StatusPotential || chainsSame[0].Links[0].DemonstratedLink {
		t.Errorf("expected POTENTIAL un-demonstrated chain before active transition check, got status=%s demo=%v",
			chainsSame[0].Status, chainsSame[0].Links[0].DemonstratedLink)
	}
}

func TestPhase5_ReconstructAttackPathAndEnrichReport_HonestyAndRedaction(t *testing.T) {
	// Unconfirmed finding MUST NOT mark steps IsDemonstrated=true
	f := report.Finding{
		ID:       "F-UNCONF",
		Title:    "Potential BOLA",
		Category: "BOLA",
		Severity: "MEDIUM",
		Target:   "http://127.0.0.1:8080/api/items?id=2",
		Endpoint: "/api/items",
		Method:   http.MethodGet,
	}
	ap := ReconstructAttackPath(f, StatusPotential, nil)
	for _, st := range ap.Steps {
		if st.IsDemonstrated {
			t.Errorf("unconfirmed attack step %d (%s) MUST NOT have IsDemonstrated=true", st.StepNumber, st.Action)
		}
		if st.Classification == "DEMONSTRATED" {
			t.Errorf("unconfirmed attack step %d MUST NOT have Classification=DEMONSTRATED", st.StepNumber)
		}
	}

	// LiveAssessmentSession.EnrichReport must not hardcode HIGH/CRITICAL/95 for POTENTIAL chain and must redact secrets
	const rawTok = "ghp_Phase5TestSecretTokenValue1234567890"
	sess := NewLiveAssessmentSession("asm-p5", "http://127.0.0.1:8080", "standard", true, nil)
	sess.InvestigatedFindings = []*InvestigatedFinding{
		{
			Finding: report.Finding{
				ID:       "F-S1",
				Title:    "Leaked Token",
				Category: "secrets",
				Severity: "HIGH",
				Target:   "http://127.0.0.1:8080/app.js",
				Endpoint: "/app.js",
				Evidence: "token=" + rawTok,
			},
			ValidationStatus: StatusConfirmed,
		},
	}
	sess.AttackChains = []AttackChain{
		{
			ID:               "chain_test_pot",
			Title:            "Potential Chain With Secret Text",
			Status:           StatusPotential,
			Summary:          "Leaked " + rawTok + " observed passively",
			FindingIDs:       []string{"F-S1"},
			DemonstratedPath: "/app.js -> /api/orders (token=" + rawTok + ")",
		},
	}

	rep := report.Report{Target: "http://127.0.0.1:8080"}
	sess.EnrichReport(&rep)
	if len(rep.AttackPaths) != 1 {
		t.Fatalf("expected 1 attack path, got %d", len(rep.AttackPaths))
	}
	p := rep.AttackPaths[0]
	if p.CombinedRiskLevel == "CRITICAL" || p.CombinedRiskScore == 95 || p.Confidence == "HIGH" {
		t.Errorf("POTENTIAL chain must not have hardcoded CRITICAL/95/HIGH metrics: level=%s score=%d conf=%s",
			p.CombinedRiskLevel, p.CombinedRiskScore, p.Confidence)
	}
	if strings.Contains(p.RiskRationale, rawTok) || strings.Contains(p.EntryPoint, rawTok) {
		t.Errorf("EnrichReport leaked raw secret token into AttackPathSummary")
	}
}
