package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"felix/pkg/compliance"
)

// TestPhase91_SampleCatalogs_EndToEnd tests end-to-end catalog loading, validation,
// identity resolution, digest stability, and limitation disclosures.
func TestPhase91_SampleCatalogs_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. OWASP ASVS Sample Catalog
	asvsJSON := `{
		"schema_version": "1.0",
		"id": "owasp-asvs-4.0",
		"title": "OWASP Application Security Verification Standard",
		"version": "4.0.3",
		"framework": "OWASP",
		"description": "Standardized application security controls for web applications and APIs.",
		"source": {
			"name": "OWASP Foundation",
			"url": "https://owasp.org/asvs",
			"publisher": "OWASP ASVS Committee",
			"license": "Creative Commons Attribution-ShareAlike 4.0",
			"is_authoritative": false,
			"limitations": "Community standard specification; requires manual and automated verification."
		},
		"controls": [
			{
				"id": "V2.1.1",
				"title": "Password Security Requirements",
				"description": "Verify that user set passwords are at least 12 characters in length.",
				"status": "active",
				"category": "Authentication",
				"severity": "HIGH",
				"references": [
					{
						"source": "NIST SP 800-63B",
						"uri": "https://pages.nist.gov/800-63-3/sp800-63b.html",
						"section": "5.1.1.2"
					}
				],
				"related_controls": ["V2.1.2"]
			},
			{
				"id": "V2.1.2",
				"title": "Password Truncation",
				"description": "Verify that passwords are not truncated upon submission.",
				"status": "active",
				"category": "Authentication",
				"severity": "MEDIUM"
			}
		],
		"metadata": {
			"tier": "Level 1",
			"applicability": "All web applications"
		}
	}`

	asvsPath := filepath.Join(tmpDir, "asvs.json")
	if err := os.WriteFile(asvsPath, []byte(asvsJSON), 0644); err != nil {
		t.Fatalf("failed writing ASVS test catalog: %v", err)
	}

	cat, err := compliance.LoadCatalog(asvsPath)
	if err != nil {
		t.Fatalf("LoadCatalog failed for ASVS sample: %v", err)
	}

	// Invariant 1: Identity
	if cat.Identity() != "owasp-asvs-4.0:4.0.3" {
		t.Errorf("expected identity owasp-asvs-4.0:4.0.3, got: %s", cat.Identity())
	}

	// Invariant 2: Digest is deterministic and non-empty
	digest1 := cat.Digest()
	if !strings.HasPrefix(digest1, "sha256:") {
		t.Fatalf("expected sha256 prefix on digest, got: %s", digest1)
	}
	digest2 := cat.Digest()
	if digest1 != digest2 {
		t.Fatalf("digest is not deterministic across repeated calls!")
	}

	// Invariant 3: Limitations Notice clearly communicates non-endorsement boundaries
	notice := cat.LimitationsNotice()
	if !strings.Contains(notice, "validation certifies that this catalog satisfies the FELIX compliance schema") {
		t.Errorf("notice missing schema certification statement: %s", notice)
	}
	if !strings.Contains(notice, "does NOT constitute official framework certification") {
		t.Errorf("notice missing non-certification warning: %s", notice)
	}
	if !strings.Contains(notice, "requires manual and automated verification") {
		t.Errorf("notice missing source limitations statement: %s", notice)
	}

	// Invariant 4: Tampering any control alters the digest
	tamperedJSON := strings.Replace(asvsJSON, "at least 12 characters", "at least 8 characters", 1)
	tamperedCat, err := compliance.LoadCatalogFromBytes([]byte(tamperedJSON))
	if err != nil {
		t.Fatalf("failed loading tampered catalog: %v", err)
	}
	if tamperedCat.Digest() == digest1 {
		t.Errorf("digest collision: tampering requirement statement did not alter digest!")
	}
}
