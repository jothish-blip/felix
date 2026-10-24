package crawler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	// Next.js Server Action patterns
	rxServerActionID  = regexp.MustCompile(`(?:\$\$ACTION_ID_|\$ACTION_ID_)([a-zA-Z0-9_-]{20,80})`)
	rxCreateServerRef = regexp.MustCompile(`createServerReference(?:_?\$\d+)?\s*\(\s*["']([a-zA-Z0-9_-]{20,80})["'](?:[^)]*?,\s*["']([a-zA-Z0-9_$]+)["'])?`)

	// Next.js Manifest patterns
	rxBuildManifest   = regexp.MustCompile(`(?:self\.__BUILD_MANIFEST|window\.__BUILD_MANIFEST)\s*=\s*(\{.+?\});`)
	rxBuildManifestCB = regexp.MustCompile(`__BUILD_MANIFEST_CB\s*\(\s*(\{.+?\})\s*\)`)

	// Webpack chunk patterns
	rxWebpackChunkFunction = regexp.MustCompile(`__webpack_require__\.u\s*=\s*function\s*\([a-zA-Z0-9_$]+\)\s*\{[^}]*?return\s+([^\;]+);`)
	rxWebpackPublicPath    = regexp.MustCompile(`__webpack_require__\.p\s*=\s*["']([^"']+)["']`)
	rxWebpackChunkJSON     = regexp.MustCompile(`\{(?:\s*["']?[a-zA-Z0-9_-]+["']?\s*:\s*["'][a-zA-Z0-9_-]+["']\s*,?)+\s*\}`)
	rxChunkPair            = regexp.MustCompile(`["']?([a-zA-Z0-9_-]+)["']?\s*:\s*["']([a-zA-Z0-9_-]+)["']`)
	rxWebpackChunkParen    = regexp.MustCompile(`\(self\.webpackChunk[a-zA-Z0-9_$]*\s*=\s*self\.webpackChunk[a-zA-Z0-9_$]*\s*\|\|\s*\[\]\)\.push\s*\(\s*\[\s*\[\s*([^\]]+)\s*\]`)

	// Metro React Native __d pattern
	rxMetroModule = regexp.MustCompile(`__d\s*\(\s*function\s*\([^)]*\)\s*\{`)

	// Generic API path literals
	rxDirectAPIPath = regexp.MustCompile(`["'](/(?:api|v[0-9]+|graphql|auth|webhook|oauth)(?:/[a-zA-Z0-9_\-\./{}:$[\]]*)?)["']`)

	// Source map reference pattern
	rxAnySourceMapURL = regexp.MustCompile(`(?m)(?://|/\*)[#@]\s*sourceMappingURL=\s*(\S+?)(?:\s*\*\/|\s*$)`)
)

// BundleExtractor coordinates AST parsing and multi-framework route discovery across JavaScript bundles.
type BundleExtractor struct {
	options BundleAnalysisOptions
}

// NewBundleExtractor creates an extraction engine with bounded options.
func NewBundleExtractor(opts BundleAnalysisOptions) *BundleExtractor {
	if opts.MaxBundleSize <= 0 {
		opts.MaxBundleSize = 10 * 1024 * 1024
	}
	if opts.MaxTokens <= 0 {
		opts.MaxTokens = 500000
	}
	return &BundleExtractor{options: opts}
}

// ExtractFromBundle analyzes a single JavaScript asset, returning route candidates, server action references,
// discovered Webpack chunk URLs, and extraction warnings.
func (be *BundleExtractor) ExtractFromBundle(content []byte, assetURL string) ([]RouteCandidate, []ServerActionReference, []string, []string) {
	var candidates []RouteCandidate
	var actions []ServerActionReference
	var chunkURLs []string
	var warnings []string

	if len(content) == 0 {
		return nil, nil, nil, nil
	}

	if int64(len(content)) > be.options.MaxBundleSize {
		warnings = append(warnings, fmt.Sprintf("Asset %s exceeds max bundle size (%d bytes); skipping AST parsing", assetURL, be.options.MaxBundleSize))
		return nil, nil, nil, warnings
	}

	src := string(content)

	// 1. Detect Framework / Bundle Type
	bundleType := "GENERIC_JS"
	if strings.Contains(src, "__webpack_require__") || strings.Contains(src, "webpackChunk") {
		bundleType = "WEB_WEBPACK"
	}
	if strings.Contains(src, "__NEXT_DATA__") || strings.Contains(src, "__BUILD_MANIFEST") || rxServerActionID.MatchString(src) {
		bundleType = "WEB_NEXTJS"
	}
	if rxMetroModule.MatchString(src) || strings.Contains(assetURL, "index.android.bundle") || strings.Contains(assetURL, "main.jsbundle") {
		bundleType = "REACT_NATIVE"
	}

	// 2. Discover Next.js Server Actions (P14.1-B)
	actions = append(actions, be.extractServerActions(src, assetURL)...)

	// 3. Discover Next.js Manifest Routes (P14.1-B)
	manifestRoutes := be.extractNextManifestRoutes(src, assetURL, bundleType)
	candidates = append(candidates, manifestRoutes...)

	// 4. Discover Webpack Chunks (P14.1-C)
	discoveredChunks := be.extractWebpackChunks(src, assetURL)
	chunkURLs = append(chunkURLs, discoveredChunks...)

	// 5. AST-Based Analysis: Lexing & Parsing (P14.1-A, P14.1-D)
	lexer := NewJSLexer(src, be.options.MaxTokens)
	tokens, err := lexer.Tokenize()
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("Lexer error on %s: %v", assetURL, err))
	}
	warnings = append(warnings, lexer.warnings...)

	parser := NewJSParser(tokens)
	astNodes, parseWarnings := parser.Parse()
	warnings = append(warnings, parseWarnings...)

	// 6. Scope constant tracking and AST traversal
	constants := make(map[string]string)
	for k, v := range be.options.CustomConstants {
		constants[k] = v
	}

	// Collect string constants
	be.collectConstants(astNodes, constants)

	// Traverse AST for API calls, route concatenations, template literals, and client definitions
	astCandidates := be.traverseAST(astNodes, constants, assetURL, bundleType)
	candidates = append(candidates, astCandidates...)

	// 7. Fallback / Regex-assisted extraction for direct string literal paths
	directCandidates := be.extractDirectStringLiterals(src, assetURL, bundleType, candidates)
	candidates = append(candidates, directCandidates...)

	// 8. Source map processing if inline data URI exists
	if be.options.IncludeSourceMaps {
		if m := rxAnySourceMapURL.FindSubmatch(content); len(m) > 1 {
			smURL := strings.TrimSpace(string(m[1]))
			if strings.HasPrefix(smURL, "data:application/json") {
				smCandidates := be.extractFromInlineSourceMap(smURL, assetURL, bundleType)
				candidates = append(candidates, smCandidates...)
			}
		}
	}

	// 9. Deduplicate candidates and normalize routes
	candidates = be.deduplicateCandidates(candidates)

	return candidates, actions, chunkURLs, warnings
}

// extractServerActions extracts Next.js Server Action references without fabricating endpoints.
func (be *BundleExtractor) extractServerActions(src, assetURL string) []ServerActionReference {
	var actions []ServerActionReference
	seen := make(map[string]bool)

	// Pattern 1: $ACTION_ID_<hash>
	for _, m := range rxServerActionID.FindAllStringSubmatch(src, -1) {
		if len(m) > 1 {
			actionID := m[1]
			if !seen[actionID] {
				seen[actionID] = true
				actions = append(actions, ServerActionReference{
					ID:             GenerateServerActionID(actionID, assetURL),
					ActionID:       actionID,
					SourceArtifact: assetURL,
					DiscoveredAt:   time.Now().UTC(),
				})
			}
		}
	}

	// Pattern 2: createServerReference("action_id", exportName)
	for _, m := range rxCreateServerRef.FindAllStringSubmatch(src, -1) {
		if len(m) > 1 {
			actionID := m[1]
			exportName := ""
			if len(m) > 2 {
				exportName = m[2]
			}
			if !seen[actionID] {
				seen[actionID] = true
				actions = append(actions, ServerActionReference{
					ID:             GenerateServerActionID(actionID, assetURL),
					ActionID:       actionID,
					ExportName:     exportName,
					SourceArtifact: assetURL,
					DiscoveredAt:   time.Now().UTC(),
				})
			}
		}
	}

	return actions
}

// extractNextManifestRoutes parses _buildManifest.js and related Next.js manifests.
func (be *BundleExtractor) extractNextManifestRoutes(src, assetURL, bundleType string) []RouteCandidate {
	var candidates []RouteCandidate

	extractRoutesFromJSON := func(rawJSON string) {
		var manifest map[string]any
		if err := json.Unmarshal([]byte(rawJSON), &manifest); err == nil {
			for routePath := range manifest {
				norm := NormalizeRouteCandidate(routePath, be.options.TargetHost)
				if norm.NormalizedPath != "" && norm.NormalizedPath != "/" && norm.IsInScope {
					candidates = append(candidates, RouteCandidate{
						ID:                GenerateRouteCandidateID(norm.NormalizedPath, "GET", assetURL),
						Path:              norm.NormalizedPath,
						RawPath:           routePath,
						HTTPMethod:        "GET",
						OriginatingAsset:  assetURL,
						BundleType:        bundleType,
						SourceType:        SourceTypeNextManifest,
						ExtractionMethod:  "NEXT_BUILD_MANIFEST",
						Confidence:        ConfidenceConfirmed,
						IsLiteral:         norm.StaticallyResolved,
						DiscoveredAt:      time.Now().UTC(),
						Evidence:          fmt.Sprintf("Declared in Next.js build manifest entry: %s", routePath),
					})
				}
			}
		}
	}

	if match := rxBuildManifest.FindStringSubmatch(src); len(match) > 1 {
		extractRoutesFromJSON(match[1])
	}
	if match := rxBuildManifestCB.FindStringSubmatch(src); len(match) > 1 {
		extractRoutesFromJSON(match[1])
	}

	return candidates
}

// extractWebpackChunks extracts runtime chunk filenames and asynchronous chunk targets.
func (be *BundleExtractor) extractWebpackChunks(src, assetURL string) []string {
	var chunkURLs []string
	seen := make(map[string]bool)

	baseURL, err := url.Parse(assetURL)
	if err != nil {
		return nil
	}

	publicPath := ""
	if match := rxWebpackPublicPath.FindStringSubmatch(src); len(match) > 1 {
		publicPath = match[1]
	}

	addChunkURL := func(relPath string) {
		relPath = strings.TrimSpace(relPath)
		if relPath == "" || seen[relPath] {
			return
		}
		seen[relPath] = true

		chunkRef := relPath
		if publicPath != "" && !strings.HasPrefix(relPath, "http") && !strings.HasPrefix(relPath, "/") {
			chunkRef = strings.TrimRight(publicPath, "/") + "/" + relPath
		}

		resolvedURL, resErr := baseURL.Parse(chunkRef)
		if resErr == nil {
			chunkURLs = append(chunkURLs, resolvedURL.String())
		}
	}

	// 1. Chunk ID map object: { 123: "a1b2", 456: "c3d4" }
	for _, block := range rxWebpackChunkJSON.FindAllString(src, -1) {
		for _, pair := range rxChunkPair.FindAllStringSubmatch(block, -1) {
			if len(pair) > 2 {
				chunkID := pair[1]
				hash := pair[2]
				addChunkURL(fmt.Sprintf("%s.%s.js", chunkID, hash))
				addChunkURL(fmt.Sprintf("static/chunks/%s.%s.js", chunkID, hash))
			}
		}
	}

	// 2. Webpack push chunk arrays: [[123], { ... }]
	for _, match := range rxWebpackChunkParen.FindAllStringSubmatch(src, -1) {
		if len(match) > 1 {
			idStr := strings.TrimSpace(match[1])
			if idStr != "" {
				addChunkURL(fmt.Sprintf("%s.js", idStr))
				addChunkURL(fmt.Sprintf("static/chunks/%s.js", idStr))
			}
		}
	}

	return chunkURLs
}

// collectConstants traverses AST nodes and records variable declarations for static concatenation resolution.
func (be *BundleExtractor) collectConstants(nodes []ASTNode, constants map[string]string) {
	for _, n := range nodes {
		if decl, ok := n.(*VariableDeclarationNode); ok {
			for _, d := range decl.Declarations {
				if d.Init != nil {
					if strLit, isStr := d.Init.(*StringLiteralNode); isStr {
						constants[d.Name] = strLit.Value
					} else if tplLit, isTpl := d.Init.(*TemplateLiteralNode); isTpl && len(tplLit.Quasis) == 1 && len(tplLit.Expressions) == 0 {
						constants[d.Name] = tplLit.Quasis[0]
					} else if binExpr, isBin := d.Init.(*BinaryExpressionNode); isBin {
						resolved := be.evalBinaryString(binExpr, constants)
						if resolved != "" {
							constants[d.Name] = resolved
						}
					}
				}
			}
		}
	}
}

// evalBinaryString evaluates a binary addition expression using known constants.
func (be *BundleExtractor) evalBinaryString(bin *BinaryExpressionNode, constants map[string]string) string {
	if bin.Operator != "+" {
		return ""
	}

	evalSide := func(side ASTNode) string {
		switch s := side.(type) {
		case *StringLiteralNode:
			return s.Value
		case *IdentifierNode:
			return constants[s.Name]
		case *BinaryExpressionNode:
			return be.evalBinaryString(s, constants)
		case *TemplateLiteralNode:
			if len(s.Quasis) == 1 && len(s.Expressions) == 0 {
				return s.Quasis[0]
			}
		}
		return ""
	}

	left := evalSide(bin.Left)
	right := evalSide(bin.Right)
	if left != "" && right != "" {
		return left + right
	}
	return ""
}

// traverseAST walks the AST to find HTTP client calls, template literals, and route mappings.
func (be *BundleExtractor) traverseAST(nodes []ASTNode, constants map[string]string, assetURL, bundleType string) []RouteCandidate {
	var candidates []RouteCandidate

	var walk func(n ASTNode)
	walk = func(n ASTNode) {
		if n == nil {
			return
		}

		switch node := n.(type) {
		case *CallExpressionNode:
			be.inspectCallExpression(node, constants, assetURL, bundleType, &candidates)
			walk(node.Callee)
			for _, arg := range node.Arguments {
				walk(arg)
			}

		case *TemplateLiteralNode:
			be.inspectTemplateLiteral(node, constants, assetURL, bundleType, &candidates)
			for _, expr := range node.Expressions {
				walk(expr)
			}

		case *BinaryExpressionNode:
			if node.Operator == "+" {
				resolved := be.evalBinaryString(node, constants)
				if strings.HasPrefix(resolved, "/") && (strings.Contains(resolved, "/api") || strings.Contains(resolved, "/v1")) {
					norm := NormalizeRouteCandidate(resolved, be.options.TargetHost)
					if norm.NormalizedPath != "" && norm.IsInScope {
						candidates = append(candidates, RouteCandidate{
							ID:                        GenerateRouteCandidateID(norm.NormalizedPath, "UNKNOWN", assetURL),
							Path:                      norm.NormalizedPath,
							RawPath:                   resolved,
							HTTPMethod:                "UNKNOWN",
							OriginatingAsset:          assetURL,
							BundleType:                bundleType,
							SourceType:                SourceTypeJavaScriptAST,
							Location:                  fmt.Sprintf("AST_CONCAT:line %d", node.Line),
							Line:                      node.Line,
							Column:                    node.Col,
							ExtractionMethod:          "AST_STRING_CONCAT",
							Confidence:                ConfidenceInferred,
							IsLiteral:                 false,
							IsStaticallyReconstructed: true,
							DiscoveredAt:              time.Now().UTC(),
						})
					}
				}
			}
			walk(node.Left)
			walk(node.Right)

		case *VariableDeclarationNode:
			for _, d := range node.Declarations {
				walk(d.Init)
			}

		case *AssignmentExpressionNode:
			walk(node.Left)
			walk(node.Right)

		case *ObjectExpressionNode:
			for _, prop := range node.Properties {
				walk(prop.Value)
			}

		case *ArrayExpressionNode:
			for _, elem := range node.Elements {
				walk(elem)
			}

		case *FunctionExpressionNode:
			for _, stmt := range node.Body {
				walk(stmt)
			}

		case *ImportExpressionNode:
			if strLit, ok := node.Source.(*StringLiteralNode); ok {
				if strings.Contains(strLit.Value, "/api") {
					norm := NormalizeRouteCandidate(strLit.Value, be.options.TargetHost)
					if norm.NormalizedPath != "" && norm.IsInScope {
						candidates = append(candidates, RouteCandidate{
							ID:               GenerateRouteCandidateID(norm.NormalizedPath, "GET", assetURL),
							Path:             norm.NormalizedPath,
							RawPath:          strLit.Value,
							HTTPMethod:       "GET",
							OriginatingAsset: assetURL,
							BundleType:       bundleType,
							SourceType:       SourceTypeWebpackChunk,
							Location:         fmt.Sprintf("DYNAMIC_IMPORT:line %d", node.Line),
							Line:             node.Line,
							Column:           node.Col,
							ExtractionMethod: "AST_DYNAMIC_IMPORT",
							Confidence:       ConfidenceConfirmed,
							IsLiteral:        true,
							DiscoveredAt:     time.Now().UTC(),
						})
					}
				}
			}
			walk(node.Source)
		}
	}

	for _, n := range nodes {
		walk(n)
	}

	return candidates
}

// inspectCallExpression identifies API client calls: fetch(), axios.<method>(), $.ajax(), etc.
func (be *BundleExtractor) inspectCallExpression(call *CallExpressionNode, constants map[string]string, assetURL, bundleType string, out *[]RouteCandidate) {
	calleeName := be.formatCalleeName(call.Callee)
	lowerCallee := strings.ToLower(calleeName)

	method := "UNKNOWN"
	switch {
	case strings.HasSuffix(lowerCallee, ".get"):
		method = "GET"
	case strings.HasSuffix(lowerCallee, ".post"):
		method = "POST"
	case strings.HasSuffix(lowerCallee, ".put"):
		method = "PUT"
	case strings.HasSuffix(lowerCallee, ".delete"):
		method = "DELETE"
	case strings.HasSuffix(lowerCallee, ".patch"):
		method = "PATCH"
	}

	// 1. fetch(url, [options])
	if calleeName == "fetch" || strings.HasSuffix(lowerCallee, ".fetch") {
		if len(call.Arguments) > 0 {
			rawURL := be.resolveNodeString(call.Arguments[0], constants)
			if rawURL != "" {
				// Check options for method
				if len(call.Arguments) > 1 {
					if obj, isObj := call.Arguments[1].(*ObjectExpressionNode); isObj {
						for _, prop := range obj.Properties {
							if strings.ToLower(prop.Key) == "method" {
								if mStr := be.resolveNodeString(prop.Value, constants); mStr != "" {
									method = strings.ToUpper(mStr)
								}
							}
						}
					}
				}
				be.addCandidateIfRoute(rawURL, method, "AST_CALL_FETCH", SourceTypeJavaScriptAST, call.Line, call.Col, assetURL, bundleType, out)
			}
		}
		return
	}

	// 2. axios.<method>(url) or axios(url, { ... }) or axios({ url: "...", method: "..." })
	if strings.HasPrefix(lowerCallee, "axios") {
		if len(call.Arguments) > 0 {
			if obj, isObj := call.Arguments[0].(*ObjectExpressionNode); isObj {
				urlVal := ""
				for _, prop := range obj.Properties {
					if strings.ToLower(prop.Key) == "url" {
						urlVal = be.resolveNodeString(prop.Value, constants)
					}
					if strings.ToLower(prop.Key) == "method" {
						if mStr := be.resolveNodeString(prop.Value, constants); mStr != "" {
							method = strings.ToUpper(mStr)
						}
					}
				}
				if urlVal != "" {
					be.addCandidateIfRoute(urlVal, method, "AST_CALL_AXIOS_OBJ", SourceTypeJavaScriptAST, call.Line, call.Col, assetURL, bundleType, out)
				}
			} else {
				rawURL := be.resolveNodeString(call.Arguments[0], constants)
				if rawURL != "" {
					be.addCandidateIfRoute(rawURL, method, "AST_CALL_AXIOS", SourceTypeJavaScriptAST, call.Line, call.Col, assetURL, bundleType, out)
				}
			}
		}
		return
	}

	// 3. React Native Metro __d(..., moduleId) module definition (P14.1-D)
	if calleeName == "__d" {
		moduleID := ""
		if len(call.Arguments) > 1 {
			moduleID = be.resolveNodeString(call.Arguments[1], constants)
		}
		// Module body is inside first argument function
		if len(call.Arguments) > 0 {
			if fn, isFn := call.Arguments[0].(*FunctionExpressionNode); isFn {
				subCandidates := be.traverseAST(fn.Body, constants, assetURL, "REACT_NATIVE")
				for i := range subCandidates {
					subCandidates[i].ModuleID = moduleID
					subCandidates[i].BundleType = "REACT_NATIVE"
					subCandidates[i].SourceType = SourceTypeReactNativeBundle
				}
				*out = append(*out, subCandidates...)
			}
		}
		return
	}
}

// inspectTemplateLiteral extracts API paths embedded in template literals: `/api/v1/users/${id}`
func (be *BundleExtractor) inspectTemplateLiteral(tpl *TemplateLiteralNode, constants map[string]string, assetURL, bundleType string, out *[]RouteCandidate) {
	if len(tpl.Quasis) == 0 {
		return
	}

	var sb strings.Builder
	for i, q := range tpl.Quasis {
		sb.WriteString(q)
		if i < len(tpl.Expressions) {
			// If expression resolves to static constant, interpolate it; otherwise placeholder
			if ident, ok := tpl.Expressions[i].(*IdentifierNode); ok && constants[ident.Name] != "" {
				sb.WriteString(constants[ident.Name])
			} else {
				sb.WriteString("{param}")
			}
		}
	}

	reconstructed := sb.String()
	if strings.HasPrefix(reconstructed, "/") && (strings.Contains(reconstructed, "/api") || strings.Contains(reconstructed, "/v1") || strings.Contains(reconstructed, "/graphql")) {
		be.addCandidateIfRoute(reconstructed, "UNKNOWN", "AST_TEMPLATE_LITERAL", SourceTypeJavaScriptAST, tpl.Line, tpl.Col, assetURL, bundleType, out)
	}
}

// formatCalleeName turns Callee AST nodes into readable names (e.g. "axios.get", "fetch", "$http.post").
func (be *BundleExtractor) formatCalleeName(callee ASTNode) string {
	switch c := callee.(type) {
	case *IdentifierNode:
		return c.Name
	case *MemberExpressionNode:
		objName := be.formatCalleeName(c.Object)
		propName := be.formatCalleeName(c.Property)
		return objName + "." + propName
	}
	return ""
}

// resolveNodeString extracts the string value of a node or evaluates it against known constants.
func (be *BundleExtractor) resolveNodeString(node ASTNode, constants map[string]string) string {
	if node == nil {
		return ""
	}
	switch n := node.(type) {
	case *StringLiteralNode:
		return n.Value
	case *IdentifierNode:
		return constants[n.Name]
	case *BinaryExpressionNode:
		return be.evalBinaryString(n, constants)
	case *TemplateLiteralNode:
		if len(n.Quasis) == 1 && len(n.Expressions) == 0 {
			return n.Quasis[0]
		}
	}
	return ""
}

// addCandidateIfRoute normalizes and validates a candidate path before adding it to output.
func (be *BundleExtractor) addCandidateIfRoute(rawPath, method, extractionMethod string, sourceType RouteCandidateSourceType, line, col int, assetURL, bundleType string, out *[]RouteCandidate) {
	norm := NormalizeRouteCandidate(rawPath, be.options.TargetHost)
	if norm.NormalizedPath == "" || !norm.IsInScope {
		return
	}

	confidence := ConfidenceConfirmed
	if !norm.StaticallyResolved {
		confidence = ConfidenceInferred
	}

	*out = append(*out, RouteCandidate{
		ID:                        GenerateRouteCandidateID(norm.NormalizedPath, method, assetURL),
		Path:                      norm.NormalizedPath,
		RawPath:                   rawPath,
		HTTPMethod:                method,
		OriginatingAsset:          assetURL,
		BundleType:                bundleType,
		SourceType:                sourceType,
		Location:                  fmt.Sprintf("%s:line %d", extractionMethod, line),
		Line:                      line,
		Column:                    col,
		ExtractionMethod:          extractionMethod,
		Confidence:                confidence,
		IsLiteral:                 norm.StaticallyResolved,
		IsStaticallyReconstructed: !norm.StaticallyResolved,
		DiscoveredAt:              time.Now().UTC(),
		Warnings:                  norm.Warnings,
	})
}

// extractDirectStringLiterals finds literal API paths not captured by AST expressions.
func (be *BundleExtractor) extractDirectStringLiterals(src, assetURL, bundleType string, existing []RouteCandidate) []RouteCandidate {
	var candidates []RouteCandidate
	seen := make(map[string]bool)
	for _, c := range existing {
		seen[c.Path] = true
	}

	for _, match := range rxDirectAPIPath.FindAllStringSubmatch(src, -1) {
		if len(match) > 1 {
			rawPath := match[1]
			norm := NormalizeRouteCandidate(rawPath, be.options.TargetHost)
			if norm.NormalizedPath != "" && norm.IsInScope && !seen[norm.NormalizedPath] {
				seen[norm.NormalizedPath] = true
				candidates = append(candidates, RouteCandidate{
					ID:               GenerateRouteCandidateID(norm.NormalizedPath, "UNKNOWN", assetURL),
					Path:             norm.NormalizedPath,
					RawPath:          rawPath,
					HTTPMethod:       "UNKNOWN",
					OriginatingAsset: assetURL,
					BundleType:       bundleType,
					SourceType:       SourceTypeJavaScriptAST,
					ExtractionMethod: "DIRECT_STRING_LITERAL",
					Confidence:       ConfidenceConfirmed,
					IsLiteral:        true,
					DiscoveredAt:     time.Now().UTC(),
				})
			}
		}
	}

	return candidates
}

// extractFromInlineSourceMap extracts original source files and endpoint references from an inline data-URI source map.
func (be *BundleExtractor) extractFromInlineSourceMap(smURL, assetURL, bundleType string) []RouteCandidate {
	idx := strings.Index(smURL, "base64,")
	if idx == -1 {
		return nil
	}
	encoded := smURL[idx+7:]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil
	}
	return be.ExtractFromSourceMapJSON(decoded, assetURL, bundleType)
}

// ExtractFromSourceMapJSON parses source map JSON bytes and extracts routes from source file paths
// and embedded source code.
func (be *BundleExtractor) ExtractFromSourceMapJSON(content []byte, assetURL, bundleType string) []RouteCandidate {
	var candidates []RouteCandidate

	var sm struct {
		Sources        []string `json:"sources"`
		SourcesContent []string `json:"sourcesContent"`
	}
	if err := json.Unmarshal(content, &sm); err != nil {
		return nil
	}

	// 1. Scan source filenames for API routes
	for _, srcFile := range sm.Sources {
		if strings.Contains(srcFile, "api/") || strings.Contains(srcFile, "pages/api") || strings.Contains(srcFile, "app/api") {
			// Convert Next.js file path to route: pages/api/users.ts -> /api/users
			routePath := cleanSourceFileToRoute(srcFile)
			if routePath != "" {
				norm := NormalizeRouteCandidate(routePath, be.options.TargetHost)
				if norm.NormalizedPath != "" && norm.IsInScope {
					candidates = append(candidates, RouteCandidate{
						ID:               GenerateRouteCandidateID(norm.NormalizedPath, "GET", assetURL),
						Path:             norm.NormalizedPath,
						RawPath:          srcFile,
						HTTPMethod:       "GET",
						OriginatingAsset: assetURL,
						BundleType:       bundleType,
						SourceType:       SourceTypeSourceMap,
						Location:         srcFile,
						ExtractionMethod: "SOURCE_MAP_PATH",
						Confidence:       ConfidenceConfirmed,
						IsLiteral:        true,
						DiscoveredAt:     time.Now().UTC(),
						Evidence:         fmt.Sprintf("Discovered in source map reference: %s", srcFile),
					})
				}
			}
		}
	}

	// 2. Scan sourcesContent if available for embedded endpoint literals
	for i, code := range sm.SourcesContent {
		srcFile := ""
		if i < len(sm.Sources) {
			srcFile = sm.Sources[i]
		}
		if code != "" {
			subCandidates := be.extractDirectStringLiterals(code, assetURL, bundleType, candidates)
			for j := range subCandidates {
				subCandidates[j].SourceType = SourceTypeSourceMap
				subCandidates[j].Location = fmt.Sprintf("SOURCE_MAP_CONTENT:%s", srcFile)
				subCandidates[j].Evidence = fmt.Sprintf("Embedded in source map content of %s", srcFile)
			}
			candidates = append(candidates, subCandidates...)
		}
	}

	return candidates
}

// cleanSourceFileToRoute maps a source file path like "pages/api/v1/auth.ts" to "/api/v1/auth".
func cleanSourceFileToRoute(filePath string) string {
	clean := strings.ReplaceAll(filePath, "\\", "/")
	for _, prefix := range []string{"pages/api", "app/api", "src/pages/api", "src/app/api", "src/api"} {
		if idx := strings.Index(clean, prefix); idx != -1 {
			sub := clean[idx+len(prefix):]
			sub = strings.TrimSuffix(sub, ".ts")
			sub = strings.TrimSuffix(sub, ".js")
			sub = strings.TrimSuffix(sub, ".tsx")
			sub = strings.TrimSuffix(sub, ".jsx")
			sub = strings.TrimSuffix(sub, "/route")
			sub = strings.TrimSuffix(sub, "/index")
			return "/api" + sub
		}
	}
	return ""
}

// deduplicateCandidates deduplicates equivalent candidates while preserving provenance.
func (be *BundleExtractor) deduplicateCandidates(candidates []RouteCandidate) []RouteCandidate {
	if len(candidates) == 0 {
		return nil
	}

	type dedupKey struct {
		path   string
		method string
	}

	seen := make(map[dedupKey]int)
	pathIdx := make(map[string]int)
	var deduped []RouteCandidate

	for _, c := range candidates {
		key := dedupKey{
			path:   c.Path,
			method: c.HTTPMethod,
		}

		if idx, exists := seen[key]; exists {
			// Merge provenance if newer match has higher confidence
			if c.Confidence == ConfidenceConfirmed && deduped[idx].Confidence != ConfidenceConfirmed {
				deduped[idx].Confidence = ConfidenceConfirmed
				deduped[idx].ExtractionMethod = c.ExtractionMethod
			}
			continue
		}

		// Check if an entry for this path already exists with UNKNOWN method
		if pIdx, pExists := pathIdx[c.Path]; pExists {
			if deduped[pIdx].HTTPMethod == "UNKNOWN" && c.HTTPMethod != "UNKNOWN" {
				// Upgrade existing entry from UNKNOWN to concrete HTTP method
				deduped[pIdx].HTTPMethod = c.HTTPMethod
				deduped[pIdx].ID = GenerateRouteCandidateID(c.Path, c.HTTPMethod, deduped[pIdx].OriginatingAsset)
				if c.Confidence == ConfidenceConfirmed {
					deduped[pIdx].Confidence = ConfidenceConfirmed
					deduped[pIdx].ExtractionMethod = c.ExtractionMethod
				}
				seen[key] = pIdx
				continue
			} else if deduped[pIdx].HTTPMethod != "UNKNOWN" && c.HTTPMethod == "UNKNOWN" {
				// We already have a specific HTTP method for this path, ignore UNKNOWN duplicate
				if c.Confidence == ConfidenceConfirmed && deduped[pIdx].Confidence != ConfidenceConfirmed {
					deduped[pIdx].Confidence = ConfidenceConfirmed
				}
				continue
			}
		}

		pathIdx[c.Path] = len(deduped)
		seen[key] = len(deduped)
		deduped = append(deduped, c)
	}

	// Sort candidates stably
	sort.Slice(deduped, func(i, j int) bool {
		if deduped[i].Path != deduped[j].Path {
			return deduped[i].Path < deduped[j].Path
		}
		return deduped[i].HTTPMethod < deduped[j].HTTPMethod
	})

	return deduped
}

// AnalyzeReactNativeBundle is an offline entrypoint for scanning React Native Metro bundles without network execution.
func AnalyzeReactNativeBundle(content []byte, assetName string, opts BundleAnalysisOptions) ([]RouteCandidate, []ServerActionReference, *BundleAnalysisReport, error) {
	extractor := NewBundleExtractor(opts)
	candidates, actions, chunks, warnings := extractor.ExtractFromBundle(content, assetName)

	report := &BundleAnalysisReport{
		TotalBundlesScanned:          1,
		TotalChunksTraversed:         len(chunks),
		TotalCandidatesDiscovered:    len(candidates),
		TotalServerActionsDiscovered: len(actions),
		Warnings:                     warnings,
	}

	return candidates, actions, report, nil
}
