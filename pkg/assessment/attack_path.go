package assessment

import (
	"fmt"

	"felix/pkg/correlation"
	"felix/pkg/report"
)

// ConvertAttackPathToSummary converts a correlation.AttackPath to a report.AttackPathSummary,
// preserving full structured node models and edge transition relationships for visual graph rendering.
func ConvertAttackPathToSummary(p correlation.AttackPath) report.AttackPathSummary {
	var transitions []string
	for _, e := range p.Edges {
		transitions = append(transitions, fmt.Sprintf("[%s] %s -> %s: %s",
			e.ValidationStatus, e.SourceTitle, e.TargetTitle, e.Explanation))
	}

	var graphNodes []report.AttackPathNode
	for i, n := range p.Nodes {
		isTarget := n.IsSensitiveData || (len(p.NodeIDs) > 0 && n.ID == p.NodeIDs[len(p.NodeIDs)-1])
		endpoint := n.Endpoint
		if endpoint == "" {
			endpoint = n.Target
		}
		graphNodes = append(graphNodes, report.AttackPathNode{
			ID:                 n.ID,
			Title:              n.Title,
			Severity:           n.Severity,
			VerificationStatus: string(n.VerificationStatus),
			Category:           n.Category,
			Endpoint:           endpoint,
			EvidenceSummary:    n.EvidenceSummary,
			IsEntrypoint:       n.IsEntrypoint || i == 0,
			IsTarget:           isTarget,
		})
	}

	var graphEdges []report.AttackPathEdge
	for _, e := range p.Edges {
		ruleName := ""
		if meta, ok := correlation.RuleCatalog[e.RuleCode]; ok {
			ruleName = meta.Name
		}
		graphEdges = append(graphEdges, report.AttackPathEdge{
			ID:                 e.ID,
			SourceID:           e.SourceFindingID,
			TargetID:           e.TargetFindingID,
			SourceTitle:        e.SourceTitle,
			TargetTitle:        e.TargetTitle,
			RuleCode:           string(e.RuleCode),
			RuleName:           ruleName,
			Type:               string(e.Type),
			ValidationStatus:   string(e.ValidationStatus),
			Confidence:         e.Confidence,
			Explanation:        e.Explanation,
			EvidenceReferences: e.EvidenceReferences,
		})
	}

	return report.AttackPathSummary{
		ID:                p.ID,
		Title:             p.Title,
		Status:            string(p.Status),
		Confidence:        p.Confidence,
		CombinedRiskLevel: p.CombinedRiskLevel,
		CombinedRiskScore: p.CombinedRiskScore,
		RiskRationale:     p.RiskRationale,
		EntryPoint:        p.EntryPoint,
		TargetAsset:       p.TargetAsset,
		PrimaryWeakness:   p.PrimaryWeakness,
		TerminalImpact:    p.TerminalImpact,
		Transitions:       transitions,
		Assumptions:       p.Assumptions,
		MissingEvidence:   p.MissingEvidence,
		Remediation:       p.Remediation,
		NodeIDs:           p.NodeIDs,
		SyntheticFixture:  p.SyntheticFixture,
		GraphNodes:        graphNodes,
		GraphEdges:        graphEdges,
	}
}

// ConvertBottleneckAnalysisToReport converts a correlation.BottleneckAnalysisResult into a report.BottleneckSummary,
// preserving the authoritative minimum-cut calculation and candidate rankings without code duplication.
func ConvertBottleneckAnalysisToReport(res *correlation.BottleneckAnalysisResult) *report.BottleneckSummary {
	if res == nil {
		return nil
	}

	var primaryRec *report.BottleneckCandidateSummary
	if res.PrimaryRecommendation != nil {
		c := res.PrimaryRecommendation
		primaryRec = &report.BottleneckCandidateSummary{
			ID:                   c.ID,
			Type:                 string(c.Type),
			Name:                 c.Name,
			Component:            c.Component,
			Endpoint:             c.Endpoint,
			AssociatedFindingIDs: c.AssociatedFindingIDs,
			DisruptedPathIDs:     c.DisruptedPathIDs,
			DisruptedCount:       c.DisruptedCount,
			TotalChains:          c.TotalChainsConsidered,
			DisruptionPercentage: c.DisruptionPercentage,
			ResidualCount:        c.ResidualCount,
			ActionableFix:        c.ActionableFix,
			Rationale:            c.Rationale,
			VerificationStatus:   c.VerificationStatus,
		}
	}

	var ranked []report.BottleneckCandidateSummary
	for _, c := range res.RankedCandidates {
		ranked = append(ranked, report.BottleneckCandidateSummary{
			ID:                   c.ID,
			Type:                 string(c.Type),
			Name:                 c.Name,
			Component:            c.Component,
			Endpoint:             c.Endpoint,
			AssociatedFindingIDs: c.AssociatedFindingIDs,
			DisruptedPathIDs:     c.DisruptedPathIDs,
			DisruptedCount:       c.DisruptedCount,
			TotalChains:          c.TotalChainsConsidered,
			DisruptionPercentage: c.DisruptionPercentage,
			ResidualCount:        c.ResidualCount,
			ActionableFix:        c.ActionableFix,
			Rationale:            c.Rationale,
			VerificationStatus:   c.VerificationStatus,
		})
	}

	minCutSize := 0
	var minCutNodes []string
	if res.MinimumCut != nil {
		minCutSize = res.MinimumCut.CutSize
		minCutNodes = res.MinimumCut.CutNodes
	}

	return &report.BottleneckSummary{
		TotalVerifiedChains:   res.TotalVerifiedChains,
		TotalCandidateChains:  res.TotalCandidateChains,
		PrimaryRecommendation: primaryRec,
		RankedCandidates:      ranked,
		MinimumCutSize:        minCutSize,
		MinimumCutNodes:       minCutNodes,
		SummaryHeadline:       res.SummaryHeadline,
	}
}
