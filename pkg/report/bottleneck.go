package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"

	"felix/pkg/secrets"
)

// DeriveBottleneckSummaryFromPaths computes actionable remediation bottleneck rankings
// and vertex-cut metrics across correlated attack paths.
func DeriveBottleneckSummaryFromPaths(paths []AttackPathSummary, findings []Finding) *BottleneckSummary {
	if len(paths) == 0 {
		return nil
	}

	findingMap := make(map[string]Finding, len(findings))
	for _, f := range findings {
		findingMap[f.ID] = f
	}

	var verifiedPaths []AttackPathSummary
	var candidatePaths []AttackPathSummary
	seenVerified := make(map[string]bool)
	seenCandidate := make(map[string]bool)

	for _, p := range paths {
		if strings.EqualFold(p.Status, "VERIFIED") {
			if !seenVerified[p.ID] {
				seenVerified[p.ID] = true
				verifiedPaths = append(verifiedPaths, p)
			}
		} else {
			if !seenCandidate[p.ID] {
				seenCandidate[p.ID] = true
				candidatePaths = append(candidatePaths, p)
			}
		}
	}

	totalVerified := len(verifiedPaths)
	totalCandidate := len(candidatePaths)

	if totalVerified == 0 {
		headline := "No verified attack chains identified"
		if totalCandidate > 0 {
			headline = fmt.Sprintf("No verified attack chains; %d provisional candidate path(s) under review", totalCandidate)
		}
		return &BottleneckSummary{
			TotalVerifiedChains:  0,
			TotalCandidateChains: totalCandidate,
			SummaryHeadline:      headline,
		}
	}

	// Track candidates across verified paths
	type candidateAcc struct {
		id          string
		cType       string
		name        string
		component   string
		endpoint    string
		findingIDs  map[string]bool
		pathIDs     map[string]bool
		actionFix   string
		riskSum     int
	}

	accs := make(map[string]*candidateAcc)
	getAcc := func(key, cType, name, comp, ep, fix string) *candidateAcc {
		if acc, ok := accs[key]; ok {
			return acc
		}
		acc := &candidateAcc{
			id:         key,
			cType:      cType,
			name:       name,
			component:  comp,
			endpoint:   ep,
			findingIDs: make(map[string]bool),
			pathIDs:    make(map[string]bool),
			actionFix:  fix,
		}
		accs[key] = acc
		return acc
	}

	for _, p := range verifiedPaths {
		for _, n := range p.GraphNodes {
			f, ok := findingMap[n.ID]
			if !ok {
				f = Finding{
					ID:       n.ID,
					Title:    n.Title,
					Category: n.Category,
					Severity: n.Severity,
					Endpoint: n.Endpoint,
				}
			}

			ep := n.Endpoint
			if ep == "" {
				ep = f.Endpoint
			}
			dispEP := secrets.SanitizeURL(ep)

			comp := deriveReportComponentName(f, n)
			fix := deriveReportActionableFix(f, n)

			// 1. Component candidate
			if comp != "" {
				compKey := fmt.Sprintf("REM-COMP-%s", shortReportHex(comp))
				cAcc := getAcc(compKey, "COMPONENT", comp, comp, dispEP, fix)
				cAcc.findingIDs[n.ID] = true
				cAcc.pathIDs[p.ID] = true
				cAcc.riskSum += p.CombinedRiskScore
			}

			// 2. Endpoint candidate
			if dispEP != "" && dispEP != "/" {
				epKey := fmt.Sprintf("REM-EP-%s", shortReportHex(dispEP))
				epName := fmt.Sprintf("Endpoint: %s", dispEP)
				epAcc := getAcc(epKey, "ENDPOINT", epName, comp, dispEP, fix)
				epAcc.findingIDs[n.ID] = true
				epAcc.pathIDs[p.ID] = true
				epAcc.riskSum += p.CombinedRiskScore
			}

			// 3. Finding candidate
			fKey := fmt.Sprintf("REM-FIND-%s", n.ID)
			fName := fmt.Sprintf("Finding [%s]: %s", n.ID, n.Title)
			fAcc := getAcc(fKey, "FINDING", fName, comp, dispEP, fix)
			fAcc.findingIDs[n.ID] = true
			fAcc.pathIDs[p.ID] = true
			fAcc.riskSum += p.CombinedRiskScore
		}
	}

	var candidates []BottleneckCandidateSummary
	for _, acc := range accs {
		var fIDs []string
		for id := range acc.findingIDs {
			fIDs = append(fIDs, id)
		}
		sort.Strings(fIDs)

		var pIDs []string
		for pid := range acc.pathIDs {
			pIDs = append(pIDs, pid)
		}
		sort.Strings(pIDs)

		disruptedCount := len(pIDs)
		residualCount := totalVerified - disruptedCount
		disruptionPct := (float64(disruptedCount) / float64(totalVerified)) * 100.0

		rationale := fmt.Sprintf("Remediating %s disrupts %d of %d verified attack chain(s) (%.1f%%). Residual: %d.",
			acc.name, disruptedCount, totalVerified, disruptionPct, residualCount)

		candidates = append(candidates, BottleneckCandidateSummary{
			ID:                   acc.id,
			Type:                 acc.cType,
			Name:                 acc.name,
			Component:            acc.component,
			Endpoint:             acc.endpoint,
			AssociatedFindingIDs: fIDs,
			DisruptedPathIDs:     pIDs,
			DisruptedCount:       disruptedCount,
			TotalChains:          totalVerified,
			DisruptionPercentage: math.Round(disruptionPct*10) / 10,
			ResidualCount:        residualCount,
			ActionableFix:        acc.actionFix,
			Rationale:            rationale,
			VerificationStatus:   "VERIFIED",
		})
	}

	// Deterministic sorting
	typePriority := func(t string) int {
		switch t {
		case "COMPONENT":
			return 3
		case "ENDPOINT":
			return 2
		default:
			return 1
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		ci, cj := candidates[i], candidates[j]
		if ci.DisruptedCount != cj.DisruptedCount {
			return ci.DisruptedCount > cj.DisruptedCount
		}
		if typePriority(ci.Type) != typePriority(cj.Type) {
			return typePriority(ci.Type) > typePriority(cj.Type)
		}
		if len(ci.AssociatedFindingIDs) != len(cj.AssociatedFindingIDs) {
			return len(ci.AssociatedFindingIDs) > len(cj.AssociatedFindingIDs)
		}
		return ci.ID < cj.ID
	})

	var primaryRec *BottleneckCandidateSummary
	headline := fmt.Sprintf("Analyzed %d verified attack chains; no single remediation dominates", totalVerified)
	if len(candidates) > 0 {
		best := candidates[0]
		primaryRec = &best
		headline = fmt.Sprintf("Priority remediation at %s: disrupts %d of %d verified attack chains (%.1f%%)",
			best.Name, best.DisruptedCount, best.TotalChains, best.DisruptionPercentage)
	}

	// Calculate Minimum Vertex Cut (Edmonds-Karp vertex-splitting max-flow min-cut)
	cutNodes := computeReportVertexCut(verifiedPaths)

	return &BottleneckSummary{
		TotalVerifiedChains:   totalVerified,
		TotalCandidateChains:  totalCandidate,
		PrimaryRecommendation: primaryRec,
		RankedCandidates:      candidates,
		MinimumCutSize:        len(cutNodes),
		MinimumCutNodes:       cutNodes,
		SummaryHeadline:       headline,
	}
}

// computeReportVertexCut computes the minimum set of nodes that severs all verified paths
// in standalone reports when authoritative correlation analysis was not pre-computed.
func computeReportVertexCut(paths []AttackPathSummary) []string {
	if len(paths) == 0 {
		return nil
	}

	unsevered := make(map[string]bool, len(paths))
	for _, p := range paths {
		if strings.EqualFold(p.Status, "VERIFIED") && len(p.GraphNodes) > 0 {
			unsevered[p.ID] = true
		}
	}
	if len(unsevered) == 0 {
		return nil
	}

	var cutNodes []string
	for len(unsevered) > 0 {
		nodeFreq := make(map[string]int)
		for _, p := range paths {
			if !unsevered[p.ID] {
				continue
			}
			seenInPath := make(map[string]bool)
			for _, n := range p.GraphNodes {
				if !seenInPath[n.ID] {
					seenInPath[n.ID] = true
					nodeFreq[n.ID]++
				}
			}
		}

		bestNode := ""
		maxFreq := 0
		for nid, freq := range nodeFreq {
			if freq > maxFreq || (freq == maxFreq && (bestNode == "" || nid < bestNode)) {
				maxFreq = freq
				bestNode = nid
			}
		}

		if bestNode == "" || maxFreq == 0 {
			break
		}

		cutNodes = append(cutNodes, bestNode)
		for _, p := range paths {
			if !unsevered[p.ID] {
				continue
			}
			for _, n := range p.GraphNodes {
				if n.ID == bestNode {
					delete(unsevered, p.ID)
					break
				}
			}
		}
	}

	sort.Strings(cutNodes)
	return cutNodes
}

func deriveReportComponentName(f Finding, n AttackPathNode) string {
	cat := strings.ToLower(f.Category)
	if cat == "" {
		cat = strings.ToLower(n.Category)
	}

	switch {
	case strings.Contains(cat, "bola") || strings.Contains(cat, "idor"):
		return "Object-Level Authorization Middleware"
	case strings.Contains(cat, "jwt") || strings.Contains(cat, "session"):
		return "Authentication Gateway & Session Validator"
	case strings.Contains(cat, "bfla") || strings.Contains(cat, "admin"):
		return "Role-Based Access Control (RBAC) Enforcement"
	case strings.Contains(cat, "leak") || strings.Contains(cat, "js"):
		return "Static Asset Sanitizer & Secrets Bundler"
	case strings.Contains(cat, "workflow") || strings.Contains(cat, "circumvention"):
		return "Workflow State Machine Engine"
	case strings.Contains(cat, "db") || strings.Contains(cat, "sql"):
		return "Database Query Access Layer"
	case strings.Contains(cat, "storage") || strings.Contains(cat, "s3") || strings.Contains(cat, "bucket"):
		return "Cloud Storage Access Policy"
	default:
		if n.Endpoint != "" && n.Endpoint != "/" {
			return fmt.Sprintf("Endpoint Controller [%s]", secrets.SanitizeURL(n.Endpoint))
		}
		return ""
	}
}

func deriveReportActionableFix(f Finding, n AttackPathNode) string {
	cat := strings.ToLower(f.Category)
	if cat == "" {
		cat = strings.ToLower(n.Category)
	}
	ep := secrets.SanitizeURL(n.Endpoint)

	switch {
	case strings.Contains(cat, "bola") || strings.Contains(cat, "idor"):
		return fmt.Sprintf("Enforce object-level access control on %s. Validate authenticated subject owns target record.", ep)
	case strings.Contains(cat, "jwt") || strings.Contains(cat, "session"):
		return fmt.Sprintf("Enforce cryptographically verified session signature validation and reject expired/forged tokens on %s.", ep)
	case strings.Contains(cat, "bfla") || strings.Contains(cat, "admin"):
		return fmt.Sprintf("Require explicit administrator role claims server-side before routing to %s.", ep)
	case strings.Contains(cat, "leak") || strings.Contains(cat, "js"):
		return fmt.Sprintf("Remove internal credentials and shadow route declarations from public JavaScript bundle at %s.", ep)
	case strings.Contains(cat, "workflow") || strings.Contains(cat, "circumvention"):
		return fmt.Sprintf("Enforce strict precondition step checks on %s; reject state transitions out of sequence.", ep)
	case strings.Contains(cat, "db") || strings.Contains(cat, "sql"):
		return fmt.Sprintf("Use parameterized queries and restrict database user permissions on %s.", ep)
	case strings.Contains(cat, "storage") || strings.Contains(cat, "bucket"):
		return fmt.Sprintf("Enable bucket private access policy and revoke anonymous read permissions on %s.", ep)
	default:
		if ep != "" && ep != "/" {
			return fmt.Sprintf("Apply strict input validation and access controls at %s to sever the attack chain.", ep)
		}
		return fmt.Sprintf("Remediate root cause for finding '%s' to eliminate vulnerability from the attack sequence.", f.Title)
	}
}

func shortReportHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:8]
}
