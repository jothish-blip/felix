package api

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

var (
	rxSecretValues = regexp.MustCompile(`(?i)(token|key|secret|password|bearer|auth|sig)=([^&#\s]+)`)
)

// DetectSensitiveIdentifiers scans route paths, query strings, schema fields, and evidence
// for identifiers relevant to multi-tenant or authorization boundaries.
func DetectSensitiveIdentifiers(rawPath string, queryParams []string, schemaProps []string, rawEvidence string) []SensitiveIdentifierHit {
	var hits []SensitiveIdentifierHit
	seen := make(map[string]bool)

	addHit := func(hit SensitiveIdentifierHit) {
		key := fmt.Sprintf("%s|%s|%s", hit.Type, hit.MatchedTerm, hit.Location)
		if !seen[key] {
			seen[key] = true
			hits = append(hits, hit)
		}
	}

	// 1. Scan Path Segments and Parameters
	if rawPath != "" {
		pathHits := scanStringForSensitiveIdentifiers(rawPath, "PATH")
		for _, h := range pathHits {
			addHit(h)
		}
	}

	// 2. Scan Query Parameter Names
	for _, qp := range queryParams {
		cleanQP := strings.TrimSpace(qp)
		if cleanQP != "" {
			qHits := scanStringForSensitiveIdentifiers(cleanQP, "QUERY")
			for _, h := range qHits {
				addHit(h)
			}
		}
	}

	// 3. Scan Schema Property Names
	for _, sp := range schemaProps {
		cleanSP := strings.TrimSpace(sp)
		if cleanSP != "" {
			sHits := scanStringForSensitiveIdentifiers(cleanSP, "SCHEMA")
			for _, h := range sHits {
				addHit(h)
			}
		}
	}

	// 4. Scan Raw Evidence snippet
	if rawEvidence != "" {
		sanitizedEv := rxSecretValues.ReplaceAllString(rawEvidence, "$1=[REDACTED]")
		eHits := scanStringForSensitiveIdentifiers(sanitizedEv, "EVIDENCE")
		for _, h := range eHits {
			addHit(h)
		}
	}

	return hits
}

// scanStringForSensitiveIdentifiers tokenizes an input string and matches authorization-boundary terms.
func scanStringForSensitiveIdentifiers(input, location string) []SensitiveIdentifierHit {
	var hits []SensitiveIdentifierHit

	// If input is a URL or query string, parse query if present
	if strings.Contains(input, "?") {
		parts := strings.SplitN(input, "?", 2)
		if location == "PATH" {
			// Scan only path part as PATH
			hits = append(hits, scanStringForSensitiveIdentifiers(parts[0], "PATH")...)
			// Scan query part as QUERY
			if u, err := url.ParseQuery(parts[1]); err == nil {
				for paramName := range u {
					hits = append(hits, scanStringForSensitiveIdentifiers(paramName, "QUERY")...)
				}
			}
			return hits
		}
	}

	tokens := tokenizeIdentifierString(input)

	for _, tok := range tokens {
		lowerTok := strings.ToLower(tok)

		// 1. User ID variants
		if lowerTok == "user_id" || lowerTok == "userid" || lowerTok == "user-id" {
			hits = append(hits, SensitiveIdentifierHit{
				Type:        SensitiveTypeUserID,
				MatchedTerm: tok,
				Location:    location,
				RawEvidence: fmt.Sprintf("Sensitive identifier %q discovered in %s", tok, location),
			})
			continue
		}

		// 2. Account ID variants
		if lowerTok == "account_id" || lowerTok == "accountid" || lowerTok == "account-id" {
			hits = append(hits, SensitiveIdentifierHit{
				Type:        SensitiveTypeAccountID,
				MatchedTerm: tok,
				Location:    location,
				RawEvidence: fmt.Sprintf("Sensitive identifier %q discovered in %s", tok, location),
			})
			continue
		}

		// 3. Tenant ID variants
		if lowerTok == "tenant_id" || lowerTok == "tenantid" || lowerTok == "tenant-id" {
			hits = append(hits, SensitiveIdentifierHit{
				Type:        SensitiveTypeTenantID,
				MatchedTerm: tok,
				Location:    location,
				RawEvidence: fmt.Sprintf("Sensitive identifier %q discovered in %s", tok, location),
			})
			continue
		}

		// 4. Org / Organization ID variants
		if lowerTok == "org_id" || lowerTok == "orgid" || lowerTok == "org-id" ||
			lowerTok == "organization_id" || lowerTok == "organizationid" || lowerTok == "organization-id" {
			hits = append(hits, SensitiveIdentifierHit{
				Type:        SensitiveTypeOrgID,
				MatchedTerm: tok,
				Location:    location,
				RawEvidence: fmt.Sprintf("Sensitive identifier %q discovered in %s", tok, location),
			})
			continue
		}

		// 5. Role variants (Strict word-boundary check to prevent matching controller, payroll, enrolled, etc.)
		if lowerTok == "role" || lowerTok == "role_id" || lowerTok == "roleid" || lowerTok == "role-id" || lowerTok == "roles" {
			hits = append(hits, SensitiveIdentifierHit{
				Type:        SensitiveTypeRole,
				MatchedTerm: tok,
				Location:    location,
				RawEvidence: fmt.Sprintf("Authorization boundary identifier %q discovered in %s", tok, location),
			})
			continue
		}

		// 6. Workspace ID variants
		if lowerTok == "workspace_id" || lowerTok == "workspaceid" || lowerTok == "workspace-id" {
			hits = append(hits, SensitiveIdentifierHit{
				Type:        SensitiveTypeWorkspaceID,
				MatchedTerm: tok,
				Location:    location,
				RawEvidence: fmt.Sprintf("Sensitive identifier %q discovered in %s", tok, location),
			})
			continue
		}

		// 7. Project ID variants
		if lowerTok == "project_id" || lowerTok == "projectid" || lowerTok == "project-id" {
			hits = append(hits, SensitiveIdentifierHit{
				Type:        SensitiveTypeProjectID,
				MatchedTerm: tok,
				Location:    location,
				RawEvidence: fmt.Sprintf("Sensitive identifier %q discovered in %s", tok, location),
			})
			continue
		}
	}

	return hits
}

// tokenizeIdentifierString splits a path or identifier by delimiters and camelCase boundaries.
// It ensures words like "controller" or "payroll" are NOT split into "role".
func tokenizeIdentifierString(input string) []string {
	var tokens []string

	// Replace non-alphanumeric path/syntax characters with spaces
	cleaned := strings.Map(func(r rune) rune {
		if r == '/' || r == '{' || r == '}' || r == '[' || r == ']' || r == ':' || r == '=' || r == '&' || r == '?' || r == '"' || r == '\'' || r == '(' || r == ')' {
			return ' '
		}
		return r
	}, input)

	fields := strings.Fields(cleaned)
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}

		// Add exact compound field (e.g. "user_id", "tenant_id", "role")
		tokens = append(tokens, f)

		// Split on underscores or dashes
		if strings.ContainsAny(f, "_-") {
			parts := strings.FieldsFunc(f, func(r rune) bool {
				return r == '_' || r == '-'
			})
			if len(parts) > 1 {
				for _, p := range parts {
					tokens = append(tokens, p)
				}
				// Also recombine e.g. "user" + "id" as "userid"
				tokens = append(tokens, strings.Join(parts, ""))
			}
		}

		// Split on camelCase boundaries: e.g. "userId" -> ["userId", "user", "id"]
		camelTokens := splitCamelCase(f)
		if len(camelTokens) > 1 {
			tokens = append(tokens, strings.Join(camelTokens, "_"))
			tokens = append(tokens, strings.Join(camelTokens, ""))
			for _, ct := range camelTokens {
				tokens = append(tokens, ct)
			}
		}
	}

	return tokens
}

// splitCamelCase decomposes camelCase and PascalCase words (e.g. "userId" -> ["user", "Id"]).
func splitCamelCase(s string) []string {
	var parts []string
	var current strings.Builder

	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if i > 0 && unicode.IsUpper(r) && !unicode.IsUpper(runes[i-1]) {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		}
		current.WriteRune(r)
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}
