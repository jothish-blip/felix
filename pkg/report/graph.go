package report

import (
	"bytes"
	"fmt"
	"html"
	"html/template"
	"strings"

	"felix/pkg/secrets"
)

// EnrichAttackPathGraph populates GraphNodes and GraphEdges on path if missing,
// resolving finding metadata from the report findings inventory.
func EnrichAttackPathGraph(path *AttackPathSummary, findings []Finding) {
	if path == nil {
		return
	}

	findingMap := make(map[string]Finding, len(findings))
	for _, f := range findings {
		findingMap[f.ID] = f
	}

	// 1. Populate GraphNodes if missing
	if len(path.GraphNodes) == 0 && len(path.NodeIDs) == 0 {
		for _, f := range findings {
			for _, tr := range path.Transitions {
				if strings.Contains(tr, f.ID) || (f.Endpoint != "" && strings.Contains(tr, f.Endpoint)) {
					path.NodeIDs = append(path.NodeIDs, f.ID)
					break
				}
			}
		}
		if len(path.NodeIDs) == 0 && len(findings) > 0 {
			count := len(findings)
			if count > 4 {
				count = 4
			}
			for i := 0; i < count; i++ {
				path.NodeIDs = append(path.NodeIDs, findings[i].ID)
			}
		}
	}

	if len(path.GraphNodes) == 0 && len(path.NodeIDs) > 0 {
		var nodes []AttackPathNode
		for i, nid := range path.NodeIDs {
			f, ok := findingMap[nid]
			isEntry := (i == 0)
			isTarget := (i == len(path.NodeIDs)-1)

			if ok {
				endpoint := f.Endpoint
				if endpoint == "" {
					endpoint = f.Target
				}
				nodes = append(nodes, AttackPathNode{
					ID:                 f.ID,
					Title:              f.Title,
					Severity:           string(f.Severity),
					VerificationStatus: string(f.Verification.Status),
					Category:           f.Category,
					Endpoint:           endpoint,
					EvidenceSummary:    f.Evidence,
					IsEntrypoint:       isEntry,
					IsTarget:           isTarget,
				})
			} else {
				// Node ID not in report findings; provide a safe fallback node
				nodes = append(nodes, AttackPathNode{
					ID:                 nid,
					Title:              nid,
					Severity:           string(SeverityInfo),
					VerificationStatus: string(VerificationObserved),
					Category:           "correlated-step",
					IsEntrypoint:       isEntry,
					IsTarget:           isTarget,
				})
			}
		}
		path.GraphNodes = nodes
	}

	// 2. Populate GraphEdges if missing
	if len(path.GraphEdges) == 0 && len(path.GraphNodes) >= 2 {
		var edges []AttackPathEdge
		for i := 0; i < len(path.GraphNodes)-1; i++ {
			src := path.GraphNodes[i]
			tgt := path.GraphNodes[i+1]

			ruleCode := "COR-01"
			ruleName := "Entry Point to Vulnerable Resource"
			relType := "REACHES"
			valStatus := path.Status
			explanation := fmt.Sprintf("Attack transition from %s to %s", src.Title, tgt.Title)

			if i == 1 {
				ruleCode = "COR-02"
				ruleName = "Authentication to Authorization"
				relType = "ENABLES"
			} else if i >= 2 {
				ruleCode = "COR-03"
				ruleName = "BOLA and Sensitive Data Exposure"
				relType = "EXPOSES"
			}

			// If transitions array has an entry for this step, parse explanation
			if i < len(path.Transitions) {
				tr := path.Transitions[i]
				if strings.Contains(tr, ": ") {
					parts := strings.SplitN(tr, ": ", 2)
					explanation = parts[1]
				}
			}

			edgeID := fmt.Sprintf("EDGE-%s-%s-%s", path.ID, src.ID, tgt.ID)
			edges = append(edges, AttackPathEdge{
				ID:               edgeID,
				SourceID:         src.ID,
				TargetID:         tgt.ID,
				SourceTitle:      src.Title,
				TargetTitle:      tgt.Title,
				RuleCode:         ruleCode,
				RuleName:         ruleName,
				Type:             relType,
				ValidationStatus: valStatus,
				Confidence:       path.Confidence,
				Explanation:      explanation,
			})
		}
		path.GraphEdges = edges
	}
}

// RenderAttackPathSVG generates a deterministic, standalone, responsive SVG visualization
// for an attack path, including styled finding nodes, directed transition arrows,
// rule code pills, and accessible data attributes for interactive inspection.
func RenderAttackPathSVG(path AttackPathSummary) template.HTML {
	if len(path.GraphNodes) == 0 {
		return template.HTML(`<div class="svg-empty-notice">No node data available for attack path visualization.</div>`)
	}

	// Deterministic column/rank assignment using DAG topological progression
	inDeg := make(map[string]int, len(path.GraphNodes))
	adj := make(map[string][]string, len(path.GraphNodes))
	for _, n := range path.GraphNodes {
		inDeg[n.ID] = 0
	}
	for _, e := range path.GraphEdges {
		inDeg[e.TargetID]++
		adj[e.SourceID] = append(adj[e.SourceID], e.TargetID)
	}

	ranks := make(map[string]int, len(path.GraphNodes))
	if len(path.GraphEdges) == 0 {
		for i, n := range path.GraphNodes {
			ranks[n.ID] = i
		}
	} else {
		// Assign ranks: roots get 0, children get parent rank + 1
		var queue []string
		for _, n := range path.GraphNodes {
			if inDeg[n.ID] == 0 {
				queue = append(queue, n.ID)
				ranks[n.ID] = 0
			}
		}
		// If all have in-degree > 0 (e.g. cycle or circular test), start from first node
		if len(queue) == 0 && len(path.GraphNodes) > 0 {
			queue = append(queue, path.GraphNodes[0].ID)
			ranks[path.GraphNodes[0].ID] = 0
		}

		visited := make(map[string]bool)
		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]
			visited[curr] = true
			currRank := ranks[curr]

			for _, next := range adj[curr] {
				if nextRank, ok := ranks[next]; !ok || currRank+1 > nextRank {
					ranks[next] = currRank + 1
				}
				if !visited[next] {
					queue = append(queue, next)
				}
			}
		}

		// Ensure every node has a rank
		for i, n := range path.GraphNodes {
			if _, ok := ranks[n.ID]; !ok {
				ranks[n.ID] = i
			}
		}
	}

	// Group nodes by rank (column)
	colGroups := make(map[int][]*AttackPathNode)
	maxRank := 0
	for i := range path.GraphNodes {
		n := &path.GraphNodes[i]
		r := ranks[n.ID]
		if r > maxRank {
			maxRank = r
		}
		colGroups[r] = append(colGroups[r], n)
	}

	maxColCount := 1
	for _, nodes := range colGroups {
		if len(nodes) > maxColCount {
			maxColCount = len(nodes)
		}
	}

	// Layout metrics
	nodeW := 210
	nodeH := 64
	colGap := 84
	rowGap := 36
	padX := 32
	padY := 32

	totalW := 2*padX + (maxRank+1)*nodeW + maxRank*colGap
	if totalW < 780 {
		totalW = 780
	}
	totalH := 2*padY + maxColCount*nodeH + (maxColCount-1)*rowGap
	if totalH < 136 {
		totalH = 136
	}

	// Node coordinates
	nodeX := make(map[string]int, len(path.GraphNodes))
	nodeY := make(map[string]int, len(path.GraphNodes))
	for r := 0; r <= maxRank; r++ {
		nodes := colGroups[r]
		numInCol := len(nodes)
		colStartX := padX + r*(nodeW+colGap)

		// Center nodes vertically within column
		colTotalH := numInCol*nodeH + (numInCol-1)*rowGap
		startOffsetY := padY + (totalH-2*padY-colTotalH)/2
		if startOffsetY < padY {
			startOffsetY = padY
		}

		for idx, n := range nodes {
			nodeX[n.ID] = colStartX
			nodeY[n.ID] = startOffsetY + idx*(nodeH+rowGap)
		}
	}

	var sb bytes.Buffer
	fmt.Fprintf(&sb, `<svg class="attack-path-svg" viewBox="0 0 %d %d" width="100%%" height="auto" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Attack Path Graph for %s">`,
		totalW, totalH, html.EscapeString(path.Title))

	// SVG Defs: Arrowhead markers
	sb.WriteString(`<defs>`)
	sb.WriteString(`<marker id="arrow-confirmed" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">`)
	sb.WriteString(`<path d="M 0 1.5 L 9 5 L 0 8.5 z" fill="#34d399"/></marker>`)
	sb.WriteString(`<marker id="arrow-candidate" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">`)
	sb.WriteString(`<path d="M 0 1.5 L 9 5 L 0 8.5 z" fill="#e5c65a"/></marker>`)
	sb.WriteString(`<marker id="arrow-inconclusive" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">`)
	sb.WriteString(`<path d="M 0 1.5 L 9 5 L 0 8.5 z" fill="#888888"/></marker>`)
	sb.WriteString(`</defs>`)

	// 1. Draw Edges
	sb.WriteString(`<g class="graph-edges" role="group" aria-label="Attack Transitions">`)
	for edgeIdx, e := range path.GraphEdges {
		x1, ok1 := nodeX[e.SourceID]
		y1, ok2 := nodeY[e.SourceID]
		x2, ok3 := nodeX[e.TargetID]
		y2, ok4 := nodeY[e.TargetID]

		if !ok1 || !ok2 || !ok3 || !ok4 {
			continue
		}

		srcRightX := x1 + nodeW
		srcMidY := y1 + nodeH/2
		tgtLeftX := x2
		tgtMidY := y2 + nodeH/2

		strokeColor := "#34d399"
		markerID := "arrow-confirmed"
		dashArray := ""

		statusUpper := strings.ToUpper(strings.TrimSpace(e.ValidationStatus))
		if statusUpper == "PLAUSIBLE" || statusUpper == "CANDIDATE" {
			strokeColor = "#e5c65a"
			markerID = "arrow-candidate"
			dashArray = ` stroke-dasharray="6,4"`
		} else if statusUpper == "INCONCLUSIVE" {
			strokeColor = "#888888"
			markerID = "arrow-inconclusive"
			dashArray = ` stroke-dasharray="3,3"`
		}

		ctrlOffset := (tgtLeftX - srcRightX) / 2
		if ctrlOffset < 20 {
			ctrlOffset = 20
		}
		pathD := fmt.Sprintf("M %d %d C %d %d, %d %d, %d %d",
			srcRightX, srcMidY,
			srcRightX+ctrlOffset, srcMidY,
			tgtLeftX-ctrlOffset, tgtMidY,
			tgtLeftX, tgtMidY)

		midX := (srcRightX + tgtLeftX) / 2
		midY := (srcMidY + tgtMidY) / 2

		fmt.Fprintf(&sb, `<g class="graph-edge-interactive" data-edge-id="%s" data-source-id="%s" data-target-id="%s" data-source-title="%s" data-target-title="%s" data-rule="%s" data-rule-name="%s" data-status="%s" data-confidence="%s" data-explanation="%s" tabindex="0" role="button" aria-label="Transition %s to %s: %s" onclick="selectGraphEdge('%s', %d)" onkeydown="handleGraphKey(event, 'edge', '%s', %d)">`,
			html.EscapeString(e.ID),
			html.EscapeString(e.SourceID),
			html.EscapeString(e.TargetID),
			html.EscapeString(e.SourceTitle),
			html.EscapeString(e.TargetTitle),
			html.EscapeString(e.RuleCode),
			html.EscapeString(e.RuleName),
			html.EscapeString(e.ValidationStatus),
			html.EscapeString(e.Confidence),
			html.EscapeString(e.Explanation),
			html.EscapeString(e.SourceID),
			html.EscapeString(e.TargetID),
			html.EscapeString(e.RuleCode),
			html.EscapeString(path.ID), edgeIdx,
			html.EscapeString(path.ID), edgeIdx,
		)

		fmt.Fprintf(&sb, `<title>%s &rarr; %s [%s: %s]&#10;%s</title>`,
			html.EscapeString(e.SourceTitle),
			html.EscapeString(e.TargetTitle),
			html.EscapeString(e.RuleCode),
			html.EscapeString(e.ValidationStatus),
			html.EscapeString(e.Explanation),
		)

		// Broad hit-area stroke for easy clicking/hovering
		fmt.Fprintf(&sb, `<path d="%s" fill="none" stroke="transparent" stroke-width="14" class="edge-hitbox"/>`, pathD)
		// Visible edge path
		fmt.Fprintf(&sb, `<path d="%s" fill="none" stroke="%s" stroke-width="2"%s marker-end="url(#%s)" class="edge-line"/>`,
			pathD, strokeColor, dashArray, markerID)

		// Rule Code Midpoint Badge
		ruleText := e.RuleCode
		if ruleText == "" {
			ruleText = "CHAIN"
		}
		pillW := 54
		pillH := 18
		fmt.Fprintf(&sb, `<rect x="%d" y="%d" width="%d" height="%d" rx="3" fill="#141414" stroke="%s" stroke-width="1" class="edge-pill-bg"/>`,
			midX-pillW/2, midY-pillH/2, pillW, pillH, strokeColor)
		fmt.Fprintf(&sb, `<text x="%d" y="%d" font-size="9.5" font-weight="700" font-family="monospace" text-anchor="middle" fill="%s">%s</text>`,
			midX, midY+4, strokeColor, html.EscapeString(ruleText))

		sb.WriteString(`</g>`)
	}
	sb.WriteString(`</g>`)

	// 2. Draw Nodes
	sb.WriteString(`<g class="graph-nodes" role="group" aria-label="Attack Path Findings">`)
	for _, n := range path.GraphNodes {
		x := nodeX[n.ID]
		y := nodeY[n.ID]

		sevBorder := "#888888"
		sevBg := "rgba(136, 136, 136, 0.15)"
		sevText := "INFO"

		switch strings.ToUpper(strings.TrimSpace(n.Severity)) {
		case "CRITICAL", "CRIT":
			sevBorder = "#ff5a5f"
			sevBg = "rgba(255, 90, 95, 0.20)"
			sevText = "CRIT"
		case "HIGH":
			sevBorder = "#ff9f43"
			sevBg = "rgba(255, 159, 67, 0.20)"
			sevText = "HIGH"
		case "MEDIUM", "MED":
			sevBorder = "#e5c65a"
			sevBg = "rgba(229, 198, 90, 0.20)"
			sevText = "MED"
		case "LOW":
			sevBorder = "#60a5fa"
			sevBg = "rgba(96, 165, 250, 0.20)"
			sevText = "LOW"
		}

		verColor := "#34d399"
		verLabel := "VERIFIED"
		vUpper := strings.ToUpper(strings.TrimSpace(n.VerificationStatus))
		switch vUpper {
		case "DETECTED", "CANDIDATE":
			verColor = "#e5c65a"
			verLabel = "CANDIDATE"
		case "OBSERVED":
			verColor = "#60a5fa"
			verLabel = "OBSERVED"
		case "NOT_EXPOSED", "DEFENDED":
			verColor = "#2dd4bf"
			verLabel = "DEFENDED"
		case "INCONCLUSIVE":
			verColor = "#888888"
			verLabel = "INCONCLUSIVE"
		}

		titleTrunc := truncateText(n.Title, 25)
		epText := n.Endpoint
		if epText == "" {
			epText = n.Category
		}
		epTrunc := truncateText(epText, 17)

		fmt.Fprintf(&sb, `<g class="graph-node-interactive" id="svg-node-%s-%s" data-node-id="%s" data-title="%s" data-severity="%s" data-verification="%s" data-category="%s" data-endpoint="%s" data-evidence="%s" tabindex="0" role="button" aria-label="Finding %s: %s, Severity %s, Status %s" onclick="selectGraphNode('%s', '%s')" onkeydown="handleGraphKey(event, 'node', '%s', '%s')">`,
			html.EscapeString(path.ID),
			html.EscapeString(n.ID),
			html.EscapeString(n.ID),
			html.EscapeString(n.Title),
			html.EscapeString(n.Severity),
			html.EscapeString(n.VerificationStatus),
			html.EscapeString(n.Category),
			html.EscapeString(secrets.SanitizeURL(n.Endpoint)),
			html.EscapeString(n.EvidenceSummary),
			html.EscapeString(n.ID),
			html.EscapeString(n.Title),
			html.EscapeString(n.Severity),
			html.EscapeString(n.VerificationStatus),
			html.EscapeString(path.ID),
			html.EscapeString(n.ID),
			html.EscapeString(path.ID),
			html.EscapeString(n.ID),
		)

		fmt.Fprintf(&sb, `<title>%s: %s&#10;Severity: %s | Status: %s&#10;Endpoint: %s</title>`,
			html.EscapeString(n.ID),
			html.EscapeString(n.Title),
			html.EscapeString(n.Severity),
			html.EscapeString(n.VerificationStatus),
			html.EscapeString(secrets.SanitizeURL(n.Endpoint)),
		)

		// Node background card with severity-accented border
		fmt.Fprintf(&sb, `<rect x="%d" y="%d" width="%d" height="%d" rx="6" fill="#0c0c0c" stroke="%s" stroke-width="1.5" class="node-bg"/>`,
			x, y, nodeW, nodeH, sevBorder)

		if n.IsEntrypoint {
			fmt.Fprintf(&sb, `<rect x="%d" y="%d" width="76" height="14" rx="3" fill="#0f172a" stroke="#38bdf8" stroke-width="0.75"/>`, x+10, y-17)
			fmt.Fprintf(&sb, `<text x="%d" y="%d" font-size="7.5" font-weight="700" font-family="sans-serif" text-anchor="middle" fill="#38bdf8">ENTRY POINT</text>`, x+48, y-7)
		} else if n.IsTarget {
			fmt.Fprintf(&sb, `<rect x="%d" y="%d" width="80" height="14" rx="3" fill="#2d1215" stroke="#ff5a5f" stroke-width="0.75"/>`, x+nodeW-90, y-17)
			fmt.Fprintf(&sb, `<text x="%d" y="%d" font-size="7.5" font-weight="700" font-family="sans-serif" text-anchor="middle" fill="#ff5a5f">TARGET ASSET</text>`, x+nodeW-50, y-7)
		}

		// Top Row: Finding ID & Severity Tag
		idDisplay := truncateText(n.ID, 16)
		fmt.Fprintf(&sb, `<text x="%d" y="%d" font-size="10.5" font-weight="700" font-family="monospace" fill="#f5f5f5">%s</text>`,
			x+10, y+16, html.EscapeString(idDisplay))

		tagW := 44
		tagH := 15
		fmt.Fprintf(&sb, `<rect x="%d" y="%d" width="%d" height="%d" rx="3" fill="%s" stroke="%s" stroke-width="0.5"/>`,
			x+nodeW-tagW-10, y+5, tagW, tagH, sevBg, sevBorder)
		fmt.Fprintf(&sb, `<text x="%d" y="%d" font-size="8.5" font-weight="700" font-family="sans-serif" text-anchor="middle" fill="%s">%s</text>`,
			x+nodeW-tagW/2-10, y+16, sevBorder, sevText)

		// Middle Row: Finding Title
		fmt.Fprintf(&sb, `<text x="%d" y="%d" font-size="11" font-weight="600" font-family="sans-serif" fill="#f5f5f5">%s</text>`,
			x+10, y+35, html.EscapeString(titleTrunc))

		// Bottom Row: Verification Status & Endpoint/Category
		verPillW := 64
		verPillH := 14
		fmt.Fprintf(&sb, `<rect x="%d" y="%d" width="%d" height="%d" rx="2" fill="#141414" stroke="%s" stroke-width="0.75"/>`,
			x+10, y+44, verPillW, verPillH, verColor)
		fmt.Fprintf(&sb, `<text x="%d" y="%d" font-size="8" font-weight="700" font-family="sans-serif" text-anchor="middle" fill="%s">%s</text>`,
			x+10+verPillW/2, y+54, verColor, verLabel)

		fmt.Fprintf(&sb, `<text x="%d" y="%d" font-size="9" font-family="monospace" fill="#a3a3a3">%s</text>`,
			x+10+verPillW+8, y+54, html.EscapeString(epTrunc))

		sb.WriteString(`</g>`)
	}
	sb.WriteString(`</g>`)
	sb.WriteString(`</svg>`)

	return template.HTML(sb.String())
}

func truncateText(s string, maxLen int) string {
	clean := strings.TrimSpace(s)
	if len(clean) <= maxLen {
		return clean
	}
	if maxLen <= 3 {
		return clean[:maxLen]
	}
	return clean[:maxLen-3] + "..."
}
