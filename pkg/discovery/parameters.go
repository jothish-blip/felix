package discovery

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	// Regex matching JSON payload object keys in JS: { key: value, "otherKey": 123 }
	jsObjectKeyRegex = regexp.MustCompile(`(?i)\b(?:data|body|params)\s*:\s*(?:JSON\.stringify\s*\(\s*)?\{([^}]+)\}`)
	jsonKeyRegex     = regexp.MustCompile(`["']?([a-zA-Z0-9_$]+)["']?\s*:`)
	// GraphQL variable declarations: ($id: ID!, $limit: Int = 10)
	graphqlVarRegex = regexp.MustCompile(`\$([a-zA-Z0-9_]+)\s*:\s*([a-zA-Z0-9_!]+)`)
)

// DiscoveredParameter describes an input accepted by an application endpoint.
type DiscoveredParameter struct {
	Name         string        `json:"name"`
	Location     ParamLocation `json:"location"` // QUERY, PATH, FORM, BODY, HEADER, COOKIE
	EndpointPath string        `json:"endpoint_path"`
	Method       string        `json:"method,omitempty"`
	InferredType string        `json:"inferred_type,omitempty"` // string, number, boolean, json, file, unknown
	Required     bool          `json:"required"`
	SourceAsset  string        `json:"source_asset,omitempty"`
	Evidence     string        `json:"evidence"`
}

// ParameterExtractor discovers, extracts, and normalizes input parameters across endpoints.
type ParameterExtractor struct{}

// NewParameterExtractor creates a ParameterExtractor instance.
func NewParameterExtractor() *ParameterExtractor {
	return &ParameterExtractor{}
}

// NormalizeEndpointWithParams standardizes an endpoint URL into a canonical route template
// and returns both the normalized route and all extracted query parameter names.
func NormalizeEndpointWithParams(rawURL string) (cleanEndpoint string, params []DiscoveredParameter) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, nil
	}

	cleanPath := parsed.Path
	if cleanPath == "" {
		cleanPath = "/"
	}
	cleanEndpoint = fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, cleanPath)

	// Extract query parameter names
	q := parsed.Query()
	var paramNames []string
	for k := range q {
		if strings.TrimSpace(k) != "" {
			paramNames = append(paramNames, strings.TrimSpace(k))
		}
	}
	sort.Strings(paramNames)

	for _, name := range paramNames {
		params = append(params, DiscoveredParameter{
			Name:         name,
			Location:     ParamLocQuery,
			EndpointPath: cleanEndpoint,
			Method:       "GET",
			InferredType: "string",
			Evidence:     fmt.Sprintf("Extracted from query string of %s", rawURL),
		})
	}

	// Extract path template parameters if present: /users/{id} or /items/:id
	pathParamRegex := regexp.MustCompile(`(?:\{([a-zA-Z0-9_]+)\}|:([a-zA-Z0-9_]+))`)
	matches := pathParamRegex.FindAllStringSubmatch(cleanPath, -1)
	for _, m := range matches {
		paramName := m[1]
		if paramName == "" {
			paramName = m[2]
		}
		if paramName != "" {
			params = append(params, DiscoveredParameter{
				Name:         paramName,
				Location:     ParamLocPath,
				EndpointPath: cleanEndpoint,
				InferredType: "string",
				Required:     true,
				Evidence:     fmt.Sprintf("Extracted from route path template segment in %s", cleanPath),
			})
		}
	}

	return cleanEndpoint, params
}

// ExtractJSRequestParameters parses JavaScript snippets for body/payload/query parameters.
func (pe *ParameterExtractor) ExtractJSRequestParameters(endpointPath, jsContent, sourceAsset string) []DiscoveredParameter {
	var params []DiscoveredParameter
	seen := make(map[string]struct{})

	// 1. JSON payload objects in fetch/axios
	objMatches := jsObjectKeyRegex.FindAllStringSubmatch(jsContent, -1)
	for _, om := range objMatches {
		if len(om) > 1 {
			bodyBlock := om[1]
			keyMatches := jsonKeyRegex.FindAllStringSubmatch(bodyBlock, -1)
			for _, km := range keyMatches {
				if len(km) > 1 {
					keyName := strings.TrimSpace(km[1])
					if keyName != "" && len(keyName) < 64 {
						k := fmt.Sprintf("BODY:%s", keyName)
						if _, exists := seen[k]; !exists {
							seen[k] = struct{}{}
							params = append(params, DiscoveredParameter{
								Name:         keyName,
								Location:     ParamLocBody,
								EndpointPath: endpointPath,
								Method:       "POST",
								SourceAsset:  sourceAsset,
								InferredType: "json_field",
								Evidence:     fmt.Sprintf("Observed in JavaScript request object block in %s", sourceAsset),
							})
						}
					}
				}
			}
		}
	}

	// 2. GraphQL variables
	if strings.Contains(jsContent, "query") || strings.Contains(jsContent, "mutation") {
		varMatches := graphqlVarRegex.FindAllStringSubmatch(jsContent, -1)
		for _, vm := range varMatches {
			if len(vm) > 2 {
				varName := strings.TrimSpace(vm[1])
				typeName := strings.TrimSpace(vm[2])
				k := fmt.Sprintf("GQL:%s", varName)
				if _, exists := seen[k]; !exists {
					seen[k] = struct{}{}
					required := strings.HasSuffix(typeName, "!")
					params = append(params, DiscoveredParameter{
						Name:         varName,
						Location:     ParamLocBody,
						EndpointPath: endpointPath,
						Method:       "POST",
						SourceAsset:  sourceAsset,
						InferredType: typeName,
						Required:     required,
						Evidence:     fmt.Sprintf("Declared as GraphQL variable ($%s: %s) in %s", varName, typeName, sourceAsset),
					})
				}
			}
		}
	}

	return params
}

// IngestParameters registers discovered parameters as inventory assets and links them to endpoints.
func (pe *ParameterExtractor) IngestParameters(
	inv *Inventory,
	asmID, execID, targetID string,
	endpointAssetID, endpointCanonical string,
	params []DiscoveredParameter,
) []string {
	var paramIDs []string

	for _, p := range params {
		paramCanonical := fmt.Sprintf("%s:%s:%s", endpointCanonical, strings.ToLower(string(p.Location)), p.Name)
		paramAsset := Asset{
			ID:              uuid.New().String(),
			AssessmentID:    asmID,
			ExecutionID:     execID,
			TargetID:        targetID,
			Type:            AssetTypeParameter,
			CanonicalID:     paramCanonical,
			ParentID:        endpointAssetID,
			DisplayName:     fmt.Sprintf("Param %s [%s]", p.Name, p.Location),
			SourceAsset:     p.SourceAsset,
			DiscoveryMethod: "STATIC_CODE_ANALYSIS",
			DiscoveryStatus: StatusObserved,
			Confidence:      ConfidenceHigh,
			InScope:         true,
			Metadata: map[string]any{
				"name":          p.Name,
				"location":      string(p.Location),
				"endpoint":      endpointCanonical,
				"method":        p.Method,
				"inferred_type": p.InferredType,
				"required":      p.Required,
			},
			Evidence: map[string]any{
				"evidence": p.Evidence,
				"source":   p.SourceAsset,
			},
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		}
		pID := inv.AddAsset(paramAsset)
		paramIDs = append(paramIDs, pID)

		// Link Endpoint ACCEPTS_PARAMETER Parameter
		if endpointAssetID != "" {
			inv.AddRelation(Relation{
				ID:            uuid.New().String(),
				AssessmentID:  asmID,
				ExecutionID:   execID,
				SourceAssetID: endpointAssetID,
				TargetAssetID: pID,
				RelationType:  RelAcceptsParameter,
				Evidence:      p.Evidence,
				Confidence:    ConfidenceHigh,
			})
		}
	}

	return paramIDs
}
