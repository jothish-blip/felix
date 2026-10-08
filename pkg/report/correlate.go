package report

import (
	"fmt"
	"strings"
)

// Correlate analyzes findings across all engines to identify interrelated security narratives.
// It synthesizes individual signals into coherent, explainable Security Stories.
func Correlate(target string, findings []Finding) ([]Finding, []SecurityStory) {
	if len(findings) == 0 {
		return nil, nil
	}

	var stories []SecurityStory

	// Helper indices
	var supabaseSecrets []Finding
	var supabaseEndpoints []string

	var firebaseOpen []Finding

	var graphqlIntrospection *Finding
	var apiDocs []Finding
	var apiRoutes []Finding

	var envFindings []Finding
	var generalSecrets []Finding

	var corsCredentialed []Finding

	for i := range findings {
		f := &findings[i]
		cat := f.Category

		// Case A: Supabase
		if strings.Contains(cat, "supabase-service") || (f.Source == SourceSecrets && strings.Contains(strings.ToLower(f.Title), "supabase service")) {
			supabaseSecrets = append(supabaseSecrets, *f)
		}
		// Collect genuine Supabase cloud project endpoints
		if strings.Contains(strings.ToLower(f.Endpoint), "supabase.co") || (f.Source == SourceCloud && strings.Contains(strings.ToLower(cat), "supabase")) {
			supabaseEndpoints = append(supabaseEndpoints, f.Endpoint)
		}

		// Case B: Firebase
		if cat == "firebase-open-database" || strings.Contains(cat, "firebase-database") {
			firebaseOpen = append(firebaseOpen, *f)
		}

		// Case C: GraphQL
		if cat == "graphql-introspection" {
			graphqlIntrospection = f
		}

		// Case D: API docs & routes
		if cat == "api-docs-exposure" {
			apiDocs = append(apiDocs, *f)
		}
		if (f.Source == SourceAPI && strings.Contains(f.Endpoint, "/api")) || strings.Contains(f.Endpoint, "/v1") {
			apiRoutes = append(apiRoutes, *f)
		}

		// Case E: .env & secrets
		if cat == "env-exposure" {
			envFindings = append(envFindings, *f)
		}
		if f.Source == SourceSecrets {
			generalSecrets = append(generalSecrets, *f)
		}

		// Case F: CORS with credentials
		if cat == "cors-origin-reflection" && f.Severity == SeverityHigh {
			corsCredentialed = append(corsCredentialed, *f)
		}
	}

	// 1. Case A — Supabase Privileged Credential + Cloud Project Endpoint
	if len(supabaseSecrets) > 0 && len(supabaseEndpoints) > 0 {
		ep := supabaseEndpoints[0]
		var relatedIDs []string
		for _, s := range supabaseSecrets {
			relatedIDs = append(relatedIDs, s.ID)
		}

		story := SecurityStory{
			ID:               fmt.Sprintf("STORY-SB-%s", shortHash(ep)),
			Title:            "Privileged Supabase Cloud Credential Exposure",
			Summary:          "A privileged Supabase service_role JWT was detected in client-side code and correlates directly with an active Supabase project endpoint.",
			Description:      fmt.Sprintf("A privileged Supabase service_role credential was discovered in client-accessible assets and matches an identified project endpoint (%s).", ep),
			Evidence: []string{
				"Client-side JavaScript assets contain a privileged Supabase service_role token pattern.",
				fmt.Sprintf("Discovered matching Supabase project endpoint: %s", ep),
				"Credential was strictly NOT transmitted or used to probe the cloud provider.",
			},
			Impact:           "A privileged service_role credential completely bypasses Row Level Security (RLS), granting administrative database access if exposed to untrusted users.",
			Severity:         SeverityCritical,
			Confidence:       ConfidenceHigh,
			RiskContribution: 10,
			InvestigateFirst: "Verify if the exposed JWT token is active in Supabase project dashboard and immediately revoke/rotate the service_role key.",
			Remediation:      RemediationFor("supabase-service-key", ""),
			RelatedIDs:       relatedIDs,
		}
		stories = append(stories, story)
	}

	// 2. Case B — Firebase Unauthorized Exposure
	for _, fb := range firebaseOpen {
		story := SecurityStory{
			ID:               fmt.Sprintf("STORY-FB-%s", shortHash(fb.Endpoint)),
			Title:            "Unauthorized Firebase Realtime Database Exposure",
			Summary:          "An open Firebase Realtime Database endpoint was verified responding with database records to unauthenticated anonymous requests.",
			Description:      fmt.Sprintf("Publicly accessible Firebase Realtime Database at %s permits unauthenticated read access.", fb.Endpoint),
			Evidence: []string{
				fmt.Sprintf("Target database endpoint: %s", fb.Endpoint),
				"Endpoint permitted unauthorized anonymous read access without authentication.",
			},
			Impact:           "Publicly open Firebase databases allow any internet user to read, download, or index sensitive application records.",
			Severity:         SeverityHigh,
			Confidence:       ConfidenceHigh,
			RiskContribution: 8,
			InvestigateFirst: "Inspect Firebase security rules in the Firebase console and restrict unauthenticated read access (.read: false or auth != null).",
			Remediation:      RemediationFor("firebase-open-database", ""),
			RelatedIDs:       []string{fb.ID},
		}
		stories = append(stories, story)
	}

	// 3. Case C — GraphQL Introspection
	if graphqlIntrospection != nil {
		hasSensitive := false
		if graphqlIntrospection.EvidenceDetails.Details != nil && graphqlIntrospection.EvidenceDetails.Details["sensitive_indicators"] != "" {
			hasSensitive = true
		} else if strings.Contains(strings.ToLower(graphqlIntrospection.Evidence), "admin") ||
			strings.Contains(strings.ToLower(graphqlIntrospection.Evidence), "user") ||
			strings.Contains(strings.ToLower(graphqlIntrospection.Evidence), "payment") ||
			strings.Contains(strings.ToLower(graphqlIntrospection.Evidence), "auth") {
			hasSensitive = true
		}

		title := "GraphQL Endpoint Discovered with Schema Introspection Enabled"
		summary := "GraphQL endpoint at the target host allows unauthenticated schema introspection, disclosing query, mutation, and schema structure."
		impact := "Public schema introspection reveals all queries, mutations, types, and fields, assisting attackers in discovering undocumented endpoints and internal data structures."
		riskContrib := 3
		if hasSensitive {
			title = "GraphQL Endpoint with Introspection Exposing Sensitive Schema Models"
			summary = "GraphQL schema introspection query confirmed accessible, disclosing business and identity model definitions (e.g. administrative, authentication, or payment types)."
			riskContrib = 5
		}

		story := SecurityStory{
			ID:               fmt.Sprintf("STORY-GQL-%s", shortHash(graphqlIntrospection.Endpoint)),
			Title:            title,
			Summary:          summary,
			Description:      fmt.Sprintf("GraphQL endpoint at %s was identified and has full introspection enabled.", graphqlIntrospection.Endpoint),
			Evidence: []string{
				fmt.Sprintf("Discovered GraphQL endpoint: %s", graphqlIntrospection.Endpoint),
				graphqlIntrospection.Evidence,
			},
			Impact:           impact,
			Severity:         SeverityMedium,
			Confidence:       ConfidenceHigh,
			RiskContribution: riskContrib,
			InvestigateFirst: "Disable GraphQL schema introspection in production configuration (e.g. set introspection: false) unless this is an intended public API.",
			Remediation:      RemediationFor("graphql-introspection", ""),
			RelatedIDs:       []string{graphqlIntrospection.ID},
		}
		stories = append(stories, story)
	}

	// 4. Case D — API Documentation Disclosed Alongside Active Endpoints
	if len(apiDocs) > 0 && len(apiRoutes) > 0 {
		doc := apiDocs[0]
		story := SecurityStory{
			ID:               fmt.Sprintf("STORY-DOC-%s", shortHash(doc.Endpoint)),
			Title:            "Public API Documentation Disclosed Alongside Active Endpoints",
			Summary:          "Public OpenAPI / Swagger specification discovered alongside referenced client API routes, mapping attack surface.",
			Description:      fmt.Sprintf("Public API schema specification at %s was discovered alongside %d referenced client API route(s).", doc.Endpoint, len(apiRoutes)),
			Evidence: []string{
				fmt.Sprintf("Public specification endpoint: %s", doc.Endpoint),
				fmt.Sprintf("Referenced client API endpoints identified: %d route(s)", len(apiRoutes)),
			},
			Impact:           "Publicly exposed API specifications disclose internal parameter definitions, schemas, and endpoint semantics.",
			Severity:         SeverityInfo,
			Confidence:       ConfidenceHigh,
			RiskContribution: 1,
			InvestigateFirst: "Verify whether the OpenAPI documentation endpoint is intended for public consumption or should be placed behind authentication.",
			Remediation:      RemediationFor("api-docs-exposure", ""),
			RelatedIDs:       []string{doc.ID},
		}
		stories = append(stories, story)
	}

	// 5. Case E — .env Exposure with Confirmed Sensitive Credentials
	if len(envFindings) > 0 {
		env := envFindings[0]
		if len(generalSecrets) > 0 {
			var related []string
			related = append(related, env.ID)
			for _, s := range generalSecrets {
				related = append(related, s.ID)
			}

			story := SecurityStory{
				ID:               fmt.Sprintf("STORY-ENV-%s", shortHash(env.Endpoint)),
				Title:            "Exposed Environment Configuration with Active Credentials",
				Summary:          "A publicly downloadable .env file was discovered alongside sensitive credential signatures, indicating severe server misconfiguration.",
				Description:      fmt.Sprintf("A public .env configuration file at %s was discovered alongside %d sensitive credential finding(s).", env.Endpoint, len(generalSecrets)),
				Evidence: []string{
					fmt.Sprintf("Environment configuration accessible at %s", env.Endpoint),
					fmt.Sprintf("Correlated with %d confirmed credential pattern(s) across target assets", len(generalSecrets)),
				},
				Impact:           "Direct exposure of production environment variables containing active secret keys permits direct compromise of connected backend databases, cloud storage, and APIs.",
				Severity:         SeverityCritical,
				Confidence:       ConfidenceHigh,
				RiskContribution: 15,
				InvestigateFirst: "Immediately block public web server access to dotfiles (.*) and revoke/rotate all secrets and database passwords declared in the .env file.",
				Remediation:      RemediationFor("env-exposure", ""),
				RelatedIDs:       related,
			}
			stories = append(stories, story)
		}
	}

	// 6. Case F — Credentialed CORS Reflection on Sensitive API Routes
	if len(corsCredentialed) > 0 && (len(apiRoutes) > 0 || graphqlIntrospection != nil) {
		cors := corsCredentialed[0]
		story := SecurityStory{
			ID:               fmt.Sprintf("STORY-CORS-%s", shortHash(cors.Endpoint)),
			Title:            "Credentialed Arbitrary-Origin CORS Reflection on Sensitive API Routes",
			Summary:          "Target endpoint reflects arbitrary Origin headers with Access-Control-Allow-Credentials: true alongside sensitive API routes, enabling authenticated data theft.",
			Description:      fmt.Sprintf("CORS configuration reflects arbitrary Origin headers with Access-Control-Allow-Credentials on %s, alongside active API endpoints.", cors.Endpoint),
			Evidence: []string{
				fmt.Sprintf("CORS arbitrary reflection endpoint: %s", cors.Endpoint),
				"Access-Control-Allow-Credentials: true enabled with reflected origin.",
				fmt.Sprintf("Discovered %d sensitive API route(s) on target host.", len(apiRoutes)),
			},
			Impact:           "Malicious external websites can trigger cross-origin authenticated requests from victim browsers to extract private user data and API responses.",
			Severity:         SeverityHigh,
			Confidence:       ConfidenceHigh,
			RiskContribution: 10,
			InvestigateFirst: "Inspect CORS middleware on the API origin; restrict allowed origins to an explicit trusted domain allowlist.",
			Remediation:      RemediationFor("cors-origin-reflection", ""),
			RelatedIDs:       []string{cors.ID},
		}
		stories = append(stories, story)
	}

	return findings, stories
}
