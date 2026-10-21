package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

type canonicalCatalog struct {
	SchemaVersion string             `json:"schema_version"`
	ID            string             `json:"id"`
	Title         string             `json:"title"`
	Version       string             `json:"version"`
	Framework     string             `json:"framework,omitempty"`
	Description   string             `json:"description,omitempty"`
	Source        *canonicalSource   `json:"source,omitempty"`
	Controls      []canonicalControl `json:"controls"`
	Metadata      map[string]any     `json:"metadata,omitempty"`
}

type canonicalSource struct {
	Name            string `json:"name,omitempty"`
	URL             string `json:"url,omitempty"`
	Publisher       string `json:"publisher,omitempty"`
	License         string `json:"license,omitempty"`
	IsAuthoritative bool   `json:"is_authoritative,omitempty"`
	Limitations     string `json:"limitations,omitempty"`
}

type canonicalControl struct {
	ID              string               `json:"id"`
	Title           string               `json:"title"`
	Description     string               `json:"description"`
	Status          string               `json:"status"`
	Category        string               `json:"category,omitempty"`
	Severity        string               `json:"severity,omitempty"`
	References      []canonicalReference `json:"references,omitempty"`
	RelatedControls []string             `json:"related_controls,omitempty"`
	Metadata        map[string]any       `json:"metadata,omitempty"`
}

type canonicalReference struct {
	Source      string `json:"source,omitempty"`
	URI         string `json:"uri,omitempty"`
	Section     string `json:"section,omitempty"`
	Description string `json:"description,omitempty"`
}

// Digest computes a deterministic SHA-256 digest of the canonicalized catalog content.
// It guarantees that:
// 1. Equivalent catalogs produce the exact same digest regardless of initial control order or map iteration order.
// 2. Changes to security-relevant content (control IDs, descriptions, statuses, titles, severities, references) yield distinct digests.
// 3. The original ControlCatalog structure is never modified or mutated.
func (c *ControlCatalog) Digest() string {
	if c == nil {
		return ""
	}
	canonical := buildCanonicalCatalog(c)
	data, err := json.Marshal(canonical)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// buildCanonicalCatalog creates a normalized, order-independent representation of a ControlCatalog.
func buildCanonicalCatalog(c *ControlCatalog) canonicalCatalog {
	cc := canonicalCatalog{
		SchemaVersion: strings.TrimSpace(c.SchemaVersion),
		ID:            strings.TrimSpace(c.ID),
		Title:         strings.TrimSpace(c.Title),
		Version:       strings.TrimSpace(c.Version),
		Framework:     strings.TrimSpace(c.Framework),
		Description:   strings.TrimSpace(c.Description),
		Metadata:      canonicalizeMetadata(c.Metadata),
	}

	if c.Source != nil {
		cc.Source = &canonicalSource{
			Name:            strings.TrimSpace(c.Source.Name),
			URL:             strings.TrimSpace(c.Source.URL),
			Publisher:       strings.TrimSpace(c.Source.Publisher),
			License:         strings.TrimSpace(c.Source.License),
			IsAuthoritative: c.Source.IsAuthoritative,
			Limitations:     strings.TrimSpace(c.Source.Limitations),
		}
	}

	// Canonicalize and sort controls
	if len(c.Controls) > 0 {
		cc.Controls = make([]canonicalControl, len(c.Controls))
		for i, ctrl := range c.Controls {
			status, _ := CanonicalControlStatus(string(ctrl.Status))
			cCtrl := canonicalControl{
				ID:          strings.TrimSpace(ctrl.ID),
				Title:       strings.TrimSpace(ctrl.Title),
				Description: strings.TrimSpace(ctrl.Description),
				Status:      string(status),
				Category:    strings.TrimSpace(ctrl.Category),
				Severity:    strings.ToUpper(strings.TrimSpace(ctrl.Severity)),
				Metadata:    canonicalizeMetadata(ctrl.Metadata),
			}

			// References
			if len(ctrl.References) > 0 {
				cCtrl.References = make([]canonicalReference, len(ctrl.References))
				for rIdx, ref := range ctrl.References {
					cCtrl.References[rIdx] = canonicalReference{
						Source:      strings.TrimSpace(ref.Source),
						URI:         strings.TrimSpace(ref.URI),
						Section:     strings.TrimSpace(ref.Section),
						Description: strings.TrimSpace(ref.Description),
					}
				}
				sort.SliceStable(cCtrl.References, func(a, b int) bool {
					rA := cCtrl.References[a]
					rB := cCtrl.References[b]
					if rA.URI != rB.URI {
						return rA.URI < rB.URI
					}
					if rA.Section != rB.Section {
						return rA.Section < rB.Section
					}
					return rA.Source < rB.Source
				})
			}

			// Related Controls
			if len(ctrl.RelatedControls) > 0 {
				rels := make([]string, len(ctrl.RelatedControls))
				for rIdx, r := range ctrl.RelatedControls {
					rels[rIdx] = strings.TrimSpace(r)
				}
				sort.Strings(rels)
				cCtrl.RelatedControls = rels
			}

			cc.Controls[i] = cCtrl
		}

		// Sort controls alphabetically by ID for order-independence
		sort.SliceStable(cc.Controls, func(i, j int) bool {
			return cc.Controls[i].ID < cc.Controls[j].ID
		})
	}

	return cc
}

func canonicalizeMetadata(meta map[string]any) map[string]any {
	if len(meta) == 0 {
		return nil
	}
	clean := make(map[string]any, len(meta))
	for k, v := range meta {
		cleanKey := strings.TrimSpace(k)
		if cleanKey == "" {
			continue
		}
		clean[cleanKey] = v
	}
	return clean
}
