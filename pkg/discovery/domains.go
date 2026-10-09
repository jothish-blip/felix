package discovery

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	// Regex matching valid fully qualified domain names and hostnames in content
	hostnameRegex = regexp.MustCompile(`\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)\b`)
	// Regex matching full URLs in code/text
	urlSchemeRegex = regexp.MustCompile(`https?://([a-zA-Z0-9\.\-]+(?::[0-9]+)?)`)
)

// ExtractRootDomain derives the apex/registrable domain from a hostname.
// Handles common two-level TLDs (e.g. co.uk, com.au) and standard single-level TLDs.
func ExtractRootDomain(hostname string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(hostname)), ".")
	if len(parts) <= 2 {
		return hostname
	}

	twoPartTLDs := map[string]struct{}{
		"co.uk": {}, "org.uk": {}, "me.uk": {}, "ltd.uk": {},
		"com.au": {}, "net.au": {}, "org.au": {},
		"co.nz": {}, "net.nz": {}, "org.nz": {},
		"co.jp": {}, "ne.jp": {}, "or.jp": {},
		"com.br": {}, "com.sg": {}, "co.in": {}, "net.in": {}, "org.in": {},
	}

	if len(parts) >= 3 {
		lastTwo := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if _, ok := twoPartTLDs[lastTwo]; ok {
			if len(parts) >= 3 {
				return parts[len(parts)-3] + "." + lastTwo
			}
			return lastTwo
		}
	}

	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// DomainExtractor extracts, normalizes, resolves, and maps domains and subdomains.
type DomainExtractor struct {
	resolver *net.Resolver
	timeout  time.Duration
}

// NewDomainExtractor creates a new domain extractor with configurable DNS timeout.
func NewDomainExtractor(timeout time.Duration) *DomainExtractor {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &DomainExtractor{
		resolver: net.DefaultResolver,
		timeout:  timeout,
	}
}

// ExtractHostnamesFromContent extracts potential hostnames from HTML/JavaScript/text content.
func ExtractHostnamesFromContent(content string) []string {
	seen := make(map[string]struct{})
	var results []string

	// 1. Extract from full URLs first
	urlMatches := urlSchemeRegex.FindAllStringSubmatch(content, -1)
	for _, m := range urlMatches {
		if len(m) > 1 {
			host := m[1]
			if idx := strings.Index(host, ":"); idx != -1 {
				host = host[:idx]
			}
			cleanHost := strings.ToLower(strings.TrimSpace(host))
			if isValidHostname(cleanHost) {
				if _, exists := seen[cleanHost]; !exists {
					seen[cleanHost] = struct{}{}
					results = append(results, cleanHost)
				}
			}
		}
	}

	// 2. Extract from raw hostnames in text
	matches := hostnameRegex.FindAllString(content, -1)
	for _, raw := range matches {
		clean := strings.ToLower(strings.TrimSpace(raw))
		if isValidHostname(clean) {
			if _, exists := seen[clean]; !exists {
				seen[clean] = struct{}{}
				results = append(results, clean)
			}
		}
	}

	return results
}

// ExtractSANHostnames extracts Subject Alternative Names from TLS certificates.
func ExtractSANHostnames(certs []*x509.Certificate) []string {
	var sans []string
	seen := make(map[string]struct{})

	for _, cert := range certs {
		if cert == nil {
			continue
		}
		if cert.Subject.CommonName != "" {
			cn := strings.ToLower(strings.TrimSpace(cert.Subject.CommonName))
			if isValidHostname(cn) && !strings.HasPrefix(cn, "*.") {
				if _, exists := seen[cn]; !exists {
					seen[cn] = struct{}{}
					sans = append(sans, cn)
				}
			}
		}
		for _, name := range cert.DNSNames {
			clean := strings.ToLower(strings.TrimSpace(name))
			if isValidHostname(clean) && !strings.HasPrefix(clean, "*.") {
				if _, exists := seen[clean]; !exists {
					seen[clean] = struct{}{}
					sans = append(sans, clean)
				}
			}
		}
	}
	return sans
}

// ResolveHostname checks DNS resolution for a discovered hostname.
func (de *DomainExtractor) ResolveHostname(ctx context.Context, hostname string) ([]string, error) {
	resolveCtx, cancel := context.WithTimeout(ctx, de.timeout)
	defer cancel()

	ips, err := de.resolver.LookupIPAddr(resolveCtx, hostname)
	if err != nil {
		return nil, err
	}

	var ipStrs []string
	for _, ip := range ips {
		ipStrs = append(ipStrs, ip.IP.String())
	}
	return ipStrs, nil
}

// ProcessTargetHost establishes the Root, Domain, Subdomain, and WebService assets for an authorized target.
func (de *DomainExtractor) ProcessTargetHost(
	ctx context.Context,
	inv *Inventory,
	asmID, execID, targetID, rawURL string,
	inScope bool,
) (domainAssetID, hostAssetID, serviceAssetID string) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return "", "", ""
	}

	host := strings.ToLower(parsed.Hostname())
	rootDomain := ExtractRootDomain(host)
	scheme := strings.ToLower(parsed.Scheme)
	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	serviceCanonical := fmt.Sprintf("%s://%s:%s", scheme, host, port)

	// 1. Root Domain Asset
	domainAsset := Asset{
		ID:              uuid.New().String(),
		AssessmentID:    asmID,
		ExecutionID:     execID,
		TargetID:        targetID,
		Type:            AssetTypeDomain,
		CanonicalID:     rootDomain,
		DisplayName:     rootDomain,
		DiscoveryMethod: "TARGET_SEED",
		DiscoveryStatus: StatusObserved,
		Confidence:      ConfidenceHigh,
		InScope:         inScope,
		Metadata: map[string]any{
			"root_domain": rootDomain,
		},
		Evidence: map[string]any{
			"seed_url": rawURL,
		},
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}
	domainAssetID = inv.AddAsset(domainAsset)

	// 2. Subdomain / Hostname Asset
	hostAsset := Asset{
		ID:              uuid.New().String(),
		AssessmentID:    asmID,
		ExecutionID:     execID,
		TargetID:        targetID,
		Type:            AssetTypeSubdomain,
		CanonicalID:     host,
		ParentID:        domainAssetID,
		DisplayName:     host,
		DiscoveryMethod: "TARGET_SEED",
		DiscoveryStatus: StatusObserved,
		Confidence:      ConfidenceHigh,
		InScope:         inScope,
		Metadata: map[string]any{
			"hostname":    host,
			"root_domain": rootDomain,
			"is_apex":     host == rootDomain,
		},
		Evidence: map[string]any{
			"target_url": rawURL,
		},
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	// Try resolving IP if target is in-scope
	if inScope {
		if ips, err := de.ResolveHostname(ctx, host); err == nil && len(ips) > 0 {
			hostAsset.DiscoveryStatus = StatusResolved
			hostAsset.Metadata["resolved_ips"] = ips
		}
	}

	hostAssetID = inv.AddAsset(hostAsset)

	// Link Domain -> Subdomain
	inv.AddRelation(Relation{
		ID:            uuid.New().String(),
		AssessmentID:  asmID,
		ExecutionID:   execID,
		SourceAssetID: domainAssetID,
		TargetAssetID: hostAssetID,
		RelationType:  RelHasSubdomain,
		Evidence:      fmt.Sprintf("%s is child of %s", host, rootDomain),
		Confidence:    ConfidenceHigh,
	})

	// 3. Web Service Asset
	serviceAsset := Asset{
		ID:              uuid.New().String(),
		AssessmentID:    asmID,
		ExecutionID:     execID,
		TargetID:        targetID,
		Type:            AssetTypeWebService,
		CanonicalID:     serviceCanonical,
		ParentID:        hostAssetID,
		DisplayName:     fmt.Sprintf("%s (%s/%s)", host, scheme, port),
		DiscoveryMethod: "TARGET_SEED",
		DiscoveryStatus: StatusReachable,
		Confidence:      ConfidenceHigh,
		InScope:         inScope,
		Metadata: map[string]any{
			"scheme": scheme,
			"host":   host,
			"port":   port,
		},
		Evidence: map[string]any{
			"target_url": rawURL,
		},
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}
	serviceAssetID = inv.AddAsset(serviceAsset)

	// Link Hostname -> Web Service
	inv.AddRelation(Relation{
		ID:            uuid.New().String(),
		AssessmentID:  asmID,
		ExecutionID:   execID,
		SourceAssetID: hostAssetID,
		TargetAssetID: serviceAssetID,
		RelationType:  RelExposesService,
		Evidence:      fmt.Sprintf("%s serves HTTP traffic at %s", host, serviceCanonical),
		Confidence:    ConfidenceHigh,
	})

	return domainAssetID, hostAssetID, serviceAssetID
}

// IngestDiscoveredHost processes a hostname found in HTML, JS, or TLS SANs.
func (de *DomainExtractor) IngestDiscoveredHost(
	ctx context.Context,
	inv *Inventory,
	asmID, execID, targetID string,
	discoveredHost, sourceAsset string,
	method string,
	isScopeAllowed func(string) bool,
	parentDomainID string,
) string {
	cleanHost := strings.ToLower(strings.TrimSpace(discoveredHost))
	if !isValidHostname(cleanHost) {
		return ""
	}

	inScope := isScopeAllowed(cleanHost)
	rootDomain := ExtractRootDomain(cleanHost)

	status := StatusObserved
	if !inScope {
		status = StatusOutOfScope
	}

	hostAsset := Asset{
		ID:              uuid.New().String(),
		AssessmentID:    asmID,
		ExecutionID:     execID,
		TargetID:        targetID,
		Type:            AssetTypeSubdomain,
		CanonicalID:     cleanHost,
		ParentID:        parentDomainID,
		DisplayName:     cleanHost,
		SourceAsset:     sourceAsset,
		DiscoveryMethod: method,
		DiscoveryStatus: status,
		Confidence:      ConfidenceMedium,
		InScope:         inScope,
		Metadata: map[string]any{
			"hostname":    cleanHost,
			"root_domain": rootDomain,
			"third_party": !inScope,
		},
		Evidence: map[string]any{
			"source": sourceAsset,
			"method": method,
		},
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	// Only resolve DNS if in scope or explicitly safe
	if inScope {
		if ips, err := de.ResolveHostname(ctx, cleanHost); err == nil && len(ips) > 0 {
			hostAsset.DiscoveryStatus = StatusResolved
			hostAsset.Metadata["resolved_ips"] = ips
		}
	}

	hostID := inv.AddAsset(hostAsset)

	if parentDomainID != "" {
		inv.AddRelation(Relation{
			ID:            uuid.New().String(),
			AssessmentID:  asmID,
			ExecutionID:   execID,
			SourceAssetID: parentDomainID,
			TargetAssetID: hostID,
			RelationType:  RelHasSubdomain,
			Evidence:      fmt.Sprintf("Discovered via %s from %s", method, sourceAsset),
			Confidence:    ConfidenceMedium,
		})
	}

	return hostID
}

func isValidHostname(h string) bool {
	if len(h) < 3 || len(h) > 253 {
		return false
	}
	if strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") {
		return false
	}
	// Exclude obvious file extensions falsely matched as domains
	badSuffixes := []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".mjs", ".map",
		".woff", ".woff2", ".ttf", ".eot", ".ico", ".json", ".xml", ".txt",
		".html", ".htm", ".pdf", ".zip", ".tar", ".gz",
	}
	for _, s := range badSuffixes {
		if strings.HasSuffix(h, s) {
			return false
		}
	}
	// Must contain at least one dot
	if !strings.Contains(h, ".") {
		return false
	}
	return true
}
