package correlation

import (
	"fmt"
	"strings"

	"felix/pkg/report"
)

// GenerateSecurityStory synthesizes an AttackPath into a structured SecurityStory answering
// the 9 core client questions and identifying the priority remediation bottleneck.
func GenerateSecurityStory(path *AttackPath) report.SecurityStory {
	firstNode := path.Nodes[0]
	lastNode := path.Nodes[len(path.Nodes)-1]

	var weaknessTitles []string
	var evidenceItems []string
	var relatedIDs []string

	for i := range path.Nodes {
		n := &path.Nodes[i]
		weaknessTitles = append(weaknessTitles, fmt.Sprintf("Step %d: %s (%s)", i+1, n.Title, n.Endpoint))
		relatedIDs = append(relatedIDs, n.OriginalID)
	}

	for i := range path.Edges {
		e := &path.Edges[i]
		evidenceItems = append(evidenceItems, fmt.Sprintf("[%s] %s -> %s: %s",
			e.ValidationStatus, e.SourceTitle, e.TargetTitle, e.Explanation))
	}

	for _, a := range path.Assumptions {
		evidenceItems = append(evidenceItems, "Assumption: "+a)
	}

	// 1. Initial exposure
	entryDesc := path.EntryPoint
	if entryDesc == "" {
		entryDesc = firstNode.Endpoint
	}

	// 2. Action enabled & 5. Asset affected & 6. Impact
	actionEnabled := fmt.Sprintf("Traversing from %s enables access to %s.", firstNode.Title, lastNode.Title)
	impactDesc := path.TerminalImpact
	if impactDesc == "" {
		impactDesc = fmt.Sprintf("Compromise of %s via verified relationship chain.", path.TargetAsset)
	}

	// 8. Investigate first & Remediation bottleneck
	investigateFirst, remediationGuidance := deriveBottleneckRemediation(path)

	storyTitle := path.Title
	if path.Status != PathVerified && !strings.Contains(storyTitle, "Potential") && !strings.Contains(storyTitle, "Candidate") {
		storyTitle = fmt.Sprintf("Potential Attack Path: %s (Candidate)", storyTitle)
	}

	summary := fmt.Sprintf("Attack path connecting %d security condition(s) on %s. Status: %s. Combined Risk: %s.",
		len(path.Nodes), path.TargetAsset, path.Status, path.CombinedRiskLevel)

	description := fmt.Sprintf("Initial entry point at %s connects %d weakness(es): %s. %s",
		entryDesc, len(path.Nodes), strings.Join(weaknessTitles, " → "), actionEnabled)

	return report.SecurityStory{
		ID:               fmt.Sprintf("STORY-%s", path.ID),
		Title:            storyTitle,
		Summary:          summary,
		Description:      description,
		Evidence:         evidenceItems,
		Impact:           impactDesc,
		Severity:         path.CombinedRiskLevel,
		Confidence:       path.Confidence,
		RiskContribution: path.CombinedRiskScore / 10,
		InvestigateFirst: investigateFirst,
		Remediation:      remediationGuidance,
		RelatedIDs:       relatedIDs,
	}
}

// deriveBottleneckRemediation identifies the single most effective choke-point to break the attack chain.
func deriveBottleneckRemediation(path *AttackPath) (string, string) {
	for _, n := range path.Nodes {
		cat := n.NormalizedCategory
		switch {
		case strings.Contains(cat, "bola") || strings.Contains(cat, "idor"):
			return "Inspect authorization logic on object access handler; enforce tenant ownership verification at the database query layer.",
				"Enforce object-level access control on every record lookup. Verify requesting principal owns the requested object ID before returning data."
		case strings.Contains(cat, "jwt") || strings.Contains(cat, "session"):
			return "Review session validation and token signature verification on backend API gateway.",
				"Invalidate sessions server-side on logout; reject expired, tampered, or unauthenticated tokens across all protected endpoints."
		case strings.Contains(cat, "bfla") || strings.Contains(cat, "admin"):
			return "Review role-based access control (RBAC) middleware protecting administrative functions.",
				"Require verified administrator role claims server-side for all sensitive endpoints; reject requests from viewer or unprivileged roles."
		case strings.Contains(cat, "workflow") || strings.Contains(cat, "circumvention"):
			return "Verify server-side finite state machine (FSM) preconditions on the terminal workflow handler.",
				"Enforce mandatory prerequisite checks before executing state transitions; reject terminal calls where previous required steps are missing."
		case strings.Contains(cat, "public") || strings.Contains(cat, "env"):
			return "Immediately restrict public access to sensitive files and storage buckets.",
				"Block web server access to environment dotfiles (.*); configure cloud storage policies to require explicit authenticated access."
		}
	}

	// Default fallback
	firstNode := path.Nodes[0]
	return fmt.Sprintf("Investigate root cause at entry point %s.", firstNode.Endpoint),
		fmt.Sprintf("Implement defensive controls at %s to break the attack sequence.", firstNode.Endpoint)
}
