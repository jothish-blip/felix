package cloudsec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"felix/pkg/crawler"
	"felix/pkg/report"
	"github.com/google/uuid"
)

// -------------------------------------------------------------------------
// Container & Kubernetes Classifications & Constants (Phase 5.3)
// -------------------------------------------------------------------------

// ExposureClassification represents the verified security posture of container/cluster infrastructure.
type ExposureClassification string

const (
	ExposureNotReachable                    ExposureClassification = "NOT_REACHABLE"
	ExposureServiceIdentified               ExposureClassification = "SERVICE_IDENTIFIED"
	ExposureAuthenticationRequired          ExposureClassification = "AUTHENTICATION_REQUIRED"
	ExposureUnauthenticatedInfoDisclosure   ExposureClassification = "UNAUTHENTICATED_INFORMATION_DISCLOSURE"
	ExposureUnauthenticatedDockerAPIExposed ExposureClassification = "UNAUTHENTICATED_DOCKER_API_EXPOSED"
	ExposureUnauthenticatedManagementAccess ExposureClassification = "UNAUTHENTICATED_MANAGEMENT_ACCESS"
	ExposureAnonymousAPIDiscovery           ExposureClassification = "ANONYMOUS_API_DISCOVERY"
	ExposureInsecureTLSConfiguration        ExposureClassification = "INSECURE_TLS_CONFIGURATION"
	ExposureExposedManagementInterface      ExposureClassification = "EXPOSED_MANAGEMENT_INTERFACE"
	ExposureMisconfiguredContainerRuntime   ExposureClassification = "MISCONFIGURED_CONTAINER_RUNTIME"
	ExposureKubernetesAPIExposed            ExposureClassification = "KUBERNETES_API_EXPOSED"
	ExposureKubeletExposed                  ExposureClassification = "KUBELET_EXPOSED"
	ExposureEtcdExposed                     ExposureClassification = "ETCD_EXPOSED"
	ExposureAccessDenied                    ExposureClassification = "ACCESS_DENIED"
	ExposureResourceNotFound                ExposureClassification = "RESOURCE_NOT_FOUND"
	ExposureInconclusive                    ExposureClassification = "INCONCLUSIVE"
)

// InfrastructureComponent identifies the specific container or cluster component.
type InfrastructureComponent string

const (
	ComponentDockerEngine     InfrastructureComponent = "DOCKER_ENGINE"
	ComponentContainerRuntime InfrastructureComponent = "CONTAINER_RUNTIME"
	ComponentK8sAPIServer     InfrastructureComponent = "KUBERNETES_API_SERVER"
	ComponentKubelet          InfrastructureComponent = "KUBELET"
	ComponentEtcd             InfrastructureComponent = "ETCD"
	ComponentDashboard        InfrastructureComponent = "MANAGEMENT_DASHBOARD"
	ComponentAutoDetect       InfrastructureComponent = "AUTO_DETECT"
)

const (
	DefaultContainerMaxResponseSize int64         = 1024 * 1024 // 1 MB ceiling
	DefaultContainerAuditTimeout    time.Duration = 10 * time.Second
	DefaultContainerUserAgent                     = "Felix-CloudSec-ContainerK8sAuditor/3.0"
)

// -------------------------------------------------------------------------
// Target & Result Models
// -------------------------------------------------------------------------

// ContainerTarget specifies a network endpoint and optional component hint for auditing.
type ContainerTarget struct {
	RawURL        string                  `json:"raw_url"`
	Component     InfrastructureComponent `json:"component"`
	Host          string                  `json:"host"`
	Port          int                     `json:"port"`
	IsLoopback    bool                    `json:"is_loopback"`
	CustomHeaders map[string]string       `json:"custom_headers,omitempty"`
}

// ContainerAuditResult captures the complete, evidence-supported outcome of an audit.
type ContainerAuditResult struct {
	ID                string                  `json:"id"`
	Component         InfrastructureComponent `json:"component"`
	TargetURL         string                  `json:"target_url"` // Redacted canonical URL
	Classification    ExposureClassification  `json:"classification"`
	HTTPStatus        int                     `json:"http_status"`
	ServiceIdentified bool                    `json:"service_identified"`
	ServiceName       string                  `json:"service_name,omitempty"`
	VersionDisclosed  string                  `json:"version_disclosed,omitempty"`
	IsAuthenticated   bool                    `json:"is_authenticated"`
	IsUnauthenticated bool                    `json:"is_unauthenticated"`
	IsAdminAccessible bool                    `json:"is_admin_accessible"`
	TLSInsecure       bool                    `json:"tls_insecure"`
	SafeHeaders       map[string]string       `json:"safe_headers,omitempty"`
	EvidenceSummary   string                  `json:"evidence_summary"`
	Severity          string                  `json:"severity"`
	Confidence        string                  `json:"confidence"`
	Remediation       string                  `json:"remediation,omitempty"`
	AuditDuration     time.Duration           `json:"audit_duration"`
	AuditTimestamp    time.Time               `json:"audit_timestamp"`
	Finding           *report.Finding         `json:"finding,omitempty"`
}

// ContainerAuditorOptions configures the container & Kubernetes auditor.
type ContainerAuditorOptions struct {
	Client          *http.Client
	Transport       http.RoundTripper
	AllowLoopback   bool
	AllowPrivateIPs bool
	MaxResponseSize int64
	Timeout         time.Duration
	UserAgent       string
	ScopeCheck      func(urlStr string) bool
}

// ContainerK8sAuditor performs non-destructive, read-only exposure audits on container & K8s infrastructure.
type ContainerK8sAuditor struct {
	options ContainerAuditorOptions
	client  *http.Client
}

// NewContainerK8sAuditor creates a new bounded ContainerK8sAuditor.
func NewContainerK8sAuditor(opts ContainerAuditorOptions) *ContainerK8sAuditor {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultContainerAuditTimeout
	}
	if opts.MaxResponseSize <= 0 {
		opts.MaxResponseSize = DefaultContainerMaxResponseSize
	}
	if opts.UserAgent == "" {
		opts.UserAgent = DefaultContainerUserAgent
	}

	client := opts.Client
	if client == nil {
		transport := opts.Transport
		if transport == nil {
			safeOpts := crawler.SafeTransportOptions{
				Timeout:         opts.Timeout,
				AllowLoopback:   opts.AllowLoopback,
				AllowPrivateIPs: opts.AllowPrivateIPs,
			}
			transport = crawler.NewSafeTransport(safeOpts)
		}

		client = &http.Client{
			Transport: transport,
			Timeout:   opts.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("container audit: maximum redirect limit (5) exceeded")
				}
				if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
					return fmt.Errorf("container audit: redirect to unsupported scheme %q blocked", req.URL.Scheme)
				}
				if opts.ScopeCheck != nil && !opts.ScopeCheck(req.URL.String()) {
					return fmt.Errorf("container audit: redirect to %s blocked by scope policy", req.URL.String())
				}
				if !opts.AllowLoopback && isLoopbackHost(req.URL.Hostname()) {
					return fmt.Errorf("container audit: redirect to loopback address %s prohibited", req.URL.Hostname())
				}
				if isProhibitedMetadataHost(req.URL.Hostname()) {
					return fmt.Errorf("container audit: redirect to cloud metadata service %s blocked by security policy", req.URL.Hostname())
				}
				return nil
			},
		}
	}

	return &ContainerK8sAuditor{
		options: opts,
		client:  client,
	}
}

// ParseContainerTarget normalizes rawURL and infers component if not specified.
func ParseContainerTarget(rawURL string, componentHint InfrastructureComponent) (*ContainerTarget, error) {
	cleanURL := strings.TrimSpace(rawURL)
	if cleanURL == "" {
		return nil, errors.New("empty target URL")
	}

	if !strings.HasPrefix(cleanURL, "http://") && !strings.HasPrefix(cleanURL, "https://") {
		cleanURL = "http://" + cleanURL
	}

	u, err := url.Parse(cleanURL)
	if err != nil {
		return nil, fmt.Errorf("invalid container target URL: %w", err)
	}

	// Redact embedded userinfo credentials immediately
	if u.User != nil {
		u.User = nil
	}

	host := u.Hostname()
	portStr := u.Port()
	port := 0
	if portStr != "" {
		port, _ = strconv.Atoi(portStr)
	} else {
		if u.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}

	isLoopback := isLoopbackHost(host)

	// Infer component from port or hint
	comp := componentHint
	if comp == "" || comp == ComponentAutoDetect {
		switch port {
		case 2375, 2376:
			comp = ComponentDockerEngine
		case 6443, 8443:
			comp = ComponentK8sAPIServer
		case 10250, 10255:
			comp = ComponentKubelet
		case 2379, 2380:
			comp = ComponentEtcd
		case 9090:
			comp = ComponentDashboard
		default:
			comp = ComponentAutoDetect
		}
	}

	return &ContainerTarget{
		RawURL:     u.String(),
		Component:  comp,
		Host:       host,
		Port:       port,
		IsLoopback: isLoopback,
	}, nil
}

// -------------------------------------------------------------------------
// Core Dispatcher
// -------------------------------------------------------------------------

// Audit evaluates a target against container & Kubernetes exposure rules.
func (a *ContainerK8sAuditor) Audit(ctx context.Context, target ContainerTarget) (*ContainerAuditResult, error) {
	// Scope check
	if a.options.ScopeCheck != nil && !a.options.ScopeCheck(target.RawURL) {
		return nil, fmt.Errorf("target URL %s rejected: outside declared authorized scope", target.RawURL)
	}

	// Loopback gate
	if target.IsLoopback && !a.options.AllowLoopback {
		return nil, fmt.Errorf("target %s rejected: loopback targets prohibited without explicit authorization", target.RawURL)
	}

	switch target.Component {
	case ComponentDockerEngine, ComponentContainerRuntime:
		return a.AuditDocker(ctx, target)
	case ComponentK8sAPIServer:
		return a.AuditK8sAPI(ctx, target)
	case ComponentKubelet:
		return a.AuditKubelet(ctx, target)
	case ComponentEtcd:
		return a.AuditEtcd(ctx, target)
	case ComponentDashboard:
		return a.AuditDashboard(ctx, target)
	case ComponentAutoDetect:
		return a.AuditAutoDetect(ctx, target)
	default:
		return a.AuditAutoDetect(ctx, target)
	}
}

// AuditURL parses rawURL and conducts an exposure audit.
func (a *ContainerK8sAuditor) AuditURL(ctx context.Context, rawURL string, hint InfrastructureComponent) (*ContainerAuditResult, error) {
	t, err := ParseContainerTarget(rawURL, hint)
	if err != nil {
		return nil, err
	}
	return a.Audit(ctx, *t)
}

// -------------------------------------------------------------------------
// 1. Docker Remote API & Container Runtime Auditor (Section 1)
// -------------------------------------------------------------------------

// AuditDocker safely verifies exposed Docker remote daemon or container runtime interfaces.
func (a *ContainerK8sAuditor) AuditDocker(ctx context.Context, target ContainerTarget) (*ContainerAuditResult, error) {
	start := time.Now()
	res := &ContainerAuditResult{
		ID:             uuid.New().String(),
		Component:      ComponentDockerEngine,
		TargetURL:      sanitizeTargetURL(target.RawURL),
		SafeHeaders:    make(map[string]string),
		AuditTimestamp: time.Now().UTC(),
	}

	baseURL := strings.TrimRight(target.RawURL, "/")

	// Step 1: Probe /_ping
	pingURL := baseURL + "/_ping"
	reqPing, err := http.NewRequestWithContext(ctx, http.MethodGet, pingURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating Docker ping request: %w", err)
	}
	reqPing.Header.Set("User-Agent", a.options.UserAgent)

	respPing, err := a.client.Do(reqPing)
	if err != nil {
		res.Classification = ExposureNotReachable
		res.EvidenceSummary = fmt.Sprintf("Network connection to Docker API endpoint failed: %v", err)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"
		res.AuditDuration = time.Since(start)
		return res, nil
	}
	defer respPing.Body.Close()

	res.HTTPStatus = respPing.StatusCode
	extractSafeResponseHeaders(respPing.Header, res.SafeHeaders)
	bodyPing, _ := readLimitedResponse(respPing.Body, a.options.MaxResponseSize)
	strPing := strings.TrimSpace(string(bodyPing))

	// Check for HTML false positive
	if isGenericHTML(respPing.Header, bodyPing) {
		res.Classification = ExposureInconclusive
		res.EvidenceSummary = "Endpoint returned HTTP 200 with HTML web response; not an active Docker daemon API"
		res.Severity = "INFO"
		res.Confidence = "LOW"
		res.AuditDuration = time.Since(start)
		return res, nil
	}

	// If 401 or 403 -> Authentication Required
	if respPing.StatusCode == http.StatusUnauthorized || respPing.StatusCode == http.StatusForbidden {
		res.ServiceIdentified = true
		res.ServiceName = "Docker Remote API"
		res.IsAuthenticated = true
		res.Classification = ExposureAuthenticationRequired
		res.EvidenceSummary = fmt.Sprintf("Docker Remote API identified on %s but access requires authentication (HTTP %d)", target.RawURL, respPing.StatusCode)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"
		res.AuditDuration = time.Since(start)
		return res, nil
	}

	pingOK := respPing.StatusCode == http.StatusOK && strings.EqualFold(strPing, "OK")
	hasVersion := false
	hasInfo := false

	// Step 2: Probe /version (Safe read-only metadata probe)
	versionURL := baseURL + "/version"
	reqVer, errVer := http.NewRequestWithContext(ctx, http.MethodGet, versionURL, nil)
	if errVer == nil {
		reqVer.Header.Set("User-Agent", a.options.UserAgent)
		if respVer, errDo := a.client.Do(reqVer); errDo == nil {
			defer respVer.Body.Close()
			extractSafeResponseHeaders(respVer.Header, res.SafeHeaders)
			bodyVer, _ := readLimitedResponse(respVer.Body, a.options.MaxResponseSize)

			if respVer.StatusCode == http.StatusOK && !isGenericHTML(respVer.Header, bodyVer) {
				var doc struct {
					Version       string `json:"Version"`
					APIVersion    string `json:"ApiVersion"`
					MinAPIVersion string `json:"MinAPIVersion"`
					GitCommit     string `json:"GitCommit"`
					GoVersion     string `json:"GoVersion"`
					Os            string `json:"Os"`
					Arch          string `json:"Arch"`
					Components    []struct {
						Name    string `json:"Name"`
						Version string `json:"Version"`
					} `json:"Components"`
				}

				if json.Unmarshal(bodyVer, &doc) == nil && (doc.Version != "" || doc.APIVersion != "" || len(doc.Components) > 0) {
					res.ServiceIdentified = true
					res.ServiceName = "Docker Engine"
					res.VersionDisclosed = doc.Version
					if res.VersionDisclosed == "" && doc.APIVersion != "" {
						res.VersionDisclosed = "API:" + doc.APIVersion
					}

					for _, c := range doc.Components {
						if strings.Contains(strings.ToLower(c.Name), "containerd") {
							res.Component = ComponentContainerRuntime
							res.ServiceName = "Docker Engine / containerd"
						}
					}
					hasVersion = true
				}
			}
		}
	}

	// Step 3: Probe /info (Safe read-only management status query)
	infoURL := baseURL + "/info"
	reqInfo, errInfo := http.NewRequestWithContext(ctx, http.MethodGet, infoURL, nil)
	if errInfo == nil {
		reqInfo.Header.Set("User-Agent", a.options.UserAgent)
		if respInfo, errDo := a.client.Do(reqInfo); errDo == nil {
			defer respInfo.Body.Close()
			bodyInfo, _ := readLimitedResponse(respInfo.Body, a.options.MaxResponseSize)
			if respInfo.StatusCode == http.StatusOK && !isGenericHTML(respInfo.Header, bodyInfo) {
				var infoDoc struct {
					ID         string `json:"ID"`
					Containers int    `json:"Containers"`
					Images     int    `json:"Images"`
				}
				if json.Unmarshal(bodyInfo, &infoDoc) == nil && (infoDoc.ID != "" || infoDoc.Containers > 0 || infoDoc.Images > 0) {
					hasInfo = true
				}
			}
		}
	}

	// Precise Posture Classification (Section 1)
	res.AuditDuration = time.Since(start)

	if hasInfo {
		// Administrative management endpoint accessible without authentication
		res.ServiceIdentified = true
		res.IsUnauthenticated = true
		res.IsAdminAccessible = true
		res.Classification = ExposureUnauthenticatedManagementAccess
		res.EvidenceSummary = fmt.Sprintf("Unauthenticated Docker management endpoint /info accessible without authentication on %s (Engine: %s). Verified unauthenticated administrative querying of daemon status.", target.RawURL, res.VersionDisclosed)
		res.Severity = "CRITICAL"
		res.Confidence = "CONFIRMED"
		res.Remediation = "Bind Docker daemon strictly to local Unix socket or enforce mutual TLS (mTLS) with client certificate verification."
		res.Finding = res.ToFinding(target.RawURL)
		return res, nil
	}

	if pingOK && hasVersion {
		// Both reachability and API version verified without authentication
		res.ServiceIdentified = true
		res.IsUnauthenticated = true
		res.Classification = ExposureUnauthenticatedDockerAPIExposed
		res.EvidenceSummary = fmt.Sprintf("Unauthenticated Docker Remote API exposed over TCP on %s. Verified daemon reachability via /_ping and version disclosure via /version (Engine: %s); mutual TLS authentication is not enforced.", target.RawURL, res.VersionDisclosed)
		res.Severity = "HIGH"
		res.Confidence = "CONFIRMED"
		res.Remediation = "Disable unauthenticated Docker TCP binding (--tlsverify) or deploy firewall ingress barriers."
		res.Finding = res.ToFinding(target.RawURL)
		return res, nil
	}

	if hasVersion {
		// Version disclosure alone
		res.ServiceIdentified = true
		res.Classification = ExposureUnauthenticatedInfoDisclosure
		res.EvidenceSummary = fmt.Sprintf("Docker daemon version disclosed via /version on %s (Version: %s).", target.RawURL, res.VersionDisclosed)
		res.Severity = "MEDIUM"
		res.Confidence = "CONFIRMED"
		res.Remediation = "Restrict unauthenticated access to Docker daemon ports."
		res.Finding = res.ToFinding(target.RawURL)
		return res, nil
	}

	if pingOK {
		// Reachability proven via _ping alone; no admin operations executed or claimed
		res.ServiceIdentified = true
		res.ServiceName = "Docker Remote API"
		res.Classification = ExposureServiceIdentified
		res.EvidenceSummary = fmt.Sprintf("Docker Remote API identified via /_ping response 'OK' on %s. Daemon is reachable; administrative operations were not verified.", target.RawURL)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"
		return res, nil
	}

	// Fallback
	res.Classification = ExposureInconclusive
	res.EvidenceSummary = fmt.Sprintf("Endpoint %s responded with status %d but did not match recognized Docker API signatures", target.RawURL, respPing.StatusCode)
	res.Severity = "INFO"
	res.Confidence = "LOW"
	return res, nil
}

// -------------------------------------------------------------------------
// 2. Kubernetes API Server Auditor (Section 2)
// -------------------------------------------------------------------------

// AuditK8sAPI safely assesses exposed Kubernetes API servers with precise classification.
func (a *ContainerK8sAuditor) AuditK8sAPI(ctx context.Context, target ContainerTarget) (*ContainerAuditResult, error) {
	start := time.Now()
	res := &ContainerAuditResult{
		ID:             uuid.New().String(),
		Component:      ComponentK8sAPIServer,
		TargetURL:      sanitizeTargetURL(target.RawURL),
		SafeHeaders:    make(map[string]string),
		AuditTimestamp: time.Now().UTC(),
	}

	baseURL := strings.TrimRight(target.RawURL, "/")

	// Step 1: Probe /version
	versionURL := baseURL + "/version"
	reqVer, err := http.NewRequestWithContext(ctx, http.MethodGet, versionURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating K8s version request: %w", err)
	}
	reqVer.Header.Set("User-Agent", a.options.UserAgent)

	respVer, err := a.client.Do(reqVer)
	if err != nil {
		res.Classification = ExposureNotReachable
		res.EvidenceSummary = fmt.Sprintf("Network connection to Kubernetes API server failed: %v", err)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"
		res.AuditDuration = time.Since(start)
		return res, nil
	}
	defer respVer.Body.Close()

	res.HTTPStatus = respVer.StatusCode
	extractSafeResponseHeaders(respVer.Header, res.SafeHeaders)
	bodyVer, _ := readLimitedResponse(respVer.Body, a.options.MaxResponseSize)

	if isGenericHTML(respVer.Header, bodyVer) {
		res.Classification = ExposureInconclusive
		res.EvidenceSummary = "Endpoint returned HTTP 200 with HTML web page; not a Kubernetes API server"
		res.Severity = "INFO"
		res.Confidence = "LOW"
		res.AuditDuration = time.Since(start)
		return res, nil
	}

	hasVersionDisclosure := false
	var k8sVer struct {
		Major      string `json:"major"`
		Minor      string `json:"minor"`
		GitVersion string `json:"gitVersion"`
		Platform   string `json:"platform"`
	}
	if respVer.StatusCode == http.StatusOK && json.Unmarshal(bodyVer, &k8sVer) == nil && k8sVer.GitVersion != "" {
		res.ServiceIdentified = true
		res.ServiceName = "Kubernetes API Server"
		res.VersionDisclosed = k8sVer.GitVersion
		hasVersionDisclosure = true
	}

	// Step 2: Probe API discovery on /api and /apis
	discoveryOpen := false
	apiURL := baseURL + "/api"
	reqAPI, _ := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	reqAPI.Header.Set("User-Agent", a.options.UserAgent)

	respAPI, errAPI := a.client.Do(reqAPI)
	if errAPI == nil {
		defer respAPI.Body.Close()
		bodyAPI, _ := readLimitedResponse(respAPI.Body, a.options.MaxResponseSize)
		if respAPI.StatusCode == http.StatusOK && !isGenericHTML(respAPI.Header, bodyAPI) {
			var apiGroupList struct {
				Kind     string   `json:"kind"`
				Versions []string `json:"versions"`
			}
			if json.Unmarshal(bodyAPI, &apiGroupList) == nil && (apiGroupList.Kind == "APIVersions" || len(apiGroupList.Versions) > 0) {
				discoveryOpen = true
				res.ServiceIdentified = true
				res.ServiceName = "Kubernetes API Server"
			}
		} else if respAPI.StatusCode == http.StatusUnauthorized || respAPI.StatusCode == http.StatusForbidden {
			res.ServiceIdentified = true
			res.ServiceName = "Kubernetes API Server"
			res.IsAuthenticated = true
		}
	}

	// Step 3: Probe read-only workload discovery on /api/v1/namespaces (safe query, zero mutation, zero secrets)
	adminOpen := false
	nsURL := baseURL + "/api/v1/namespaces"
	reqNS, _ := http.NewRequestWithContext(ctx, http.MethodGet, nsURL, nil)
	reqNS.Header.Set("User-Agent", a.options.UserAgent)
	if respNS, errNS := a.client.Do(reqNS); errNS == nil {
		defer respNS.Body.Close()
		bodyNS, _ := readLimitedResponse(respNS.Body, a.options.MaxResponseSize)
		if respNS.StatusCode == http.StatusOK && !isGenericHTML(respNS.Header, bodyNS) {
			var nsList struct {
				Kind  string `json:"kind"`
				Items []any  `json:"items"`
			}
			if json.Unmarshal(bodyNS, &nsList) == nil && (nsList.Kind == "NamespaceList" || len(nsList.Items) > 0) {
				adminOpen = true
			}
		}
	}

	// Step 4: Check /healthz (Section 11)
	healthOK := false
	healthURL := baseURL + "/healthz"
	reqHealth, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	reqHealth.Header.Set("User-Agent", a.options.UserAgent)
	if respHealth, errH := a.client.Do(reqHealth); errH == nil {
		defer respHealth.Body.Close()
		bodyH, _ := readLimitedResponse(respHealth.Body, a.options.MaxResponseSize)
		if respHealth.StatusCode == http.StatusOK && strings.TrimSpace(string(bodyH)) == "ok" {
			healthOK = true
			res.ServiceIdentified = true
			res.ServiceName = "Kubernetes API Server"
		}
	}

	res.AuditDuration = time.Since(start)

	// Step 5: Precise Evaluation (Section 2)
	if adminOpen {
		// Confirmed unauthenticated administrative access
		res.IsUnauthenticated = true
		res.IsAdminAccessible = true
		res.Classification = ExposureKubernetesAPIExposed
		res.EvidenceSummary = fmt.Sprintf("Kubernetes API server on %s exposes unauthenticated cluster administration and namespace querying on /api/v1/namespaces.", target.RawURL)
		res.Severity = "CRITICAL"
		res.Confidence = "CONFIRMED"
		res.Remediation = "Enforce --anonymous-auth=false on kube-apiserver and configure RBAC authorization."
		res.Finding = res.ToFinding(target.RawURL)
		return res, nil
	}

	if discoveryOpen {
		// Section 2: Public /api or /apis discovery alone must NOT be classified as confirmed administrative access
		res.IsUnauthenticated = true
		res.Classification = ExposureAnonymousAPIDiscovery
		res.EvidenceSummary = fmt.Sprintf("Kubernetes API server on %s allows anonymous API discovery on /api; administrative endpoints (/api/v1/namespaces) are protected by authentication.", target.RawURL)
		res.Severity = "MEDIUM"
		res.Confidence = "CONFIRMED"
		res.Remediation = "Disable anonymous API discovery access via RBAC ClusterRoleBinding system:anonymous."
		res.Finding = res.ToFinding(target.RawURL)
		return res, nil
	}

	if hasVersionDisclosure {
		res.Classification = ExposureUnauthenticatedInfoDisclosure
		res.EvidenceSummary = fmt.Sprintf("Kubernetes API server discloses cluster build version via /version (%s); administrative operations require authentication.", res.VersionDisclosed)
		res.Severity = "LOW"
		res.Confidence = "CONFIRMED"
		res.Remediation = "Restrict unauthenticated access to /version via RBAC if cluster version obscuration is required."
		res.Finding = res.ToFinding(target.RawURL)
		return res, nil
	}

	if healthOK {
		// Section 2: Anonymous health endpoint alone is not unrestricted cluster access
		res.Classification = ExposureServiceIdentified
		res.EvidenceSummary = fmt.Sprintf("Kubernetes API server health endpoint (/healthz) reachable on %s; administrative operations and cluster metadata require authentication.", target.RawURL)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"
		return res, nil
	}

	if res.IsAuthenticated {
		res.Classification = ExposureAuthenticationRequired
		res.EvidenceSummary = fmt.Sprintf("Kubernetes API server on %s requires authentication for all surveyed endpoints (HTTP %d).", target.RawURL, res.HTTPStatus)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"
		return res, nil
	}

	res.Classification = ExposureInconclusive
	res.EvidenceSummary = fmt.Sprintf("Endpoint %s responded with status %d but did not match Kubernetes API server signatures", target.RawURL, respVer.StatusCode)
	res.Severity = "INFO"
	res.Confidence = "LOW"
	return res, nil
}

// -------------------------------------------------------------------------
// 3. Kubelet Exposure Auditor (Section 3)
// -------------------------------------------------------------------------

// AuditKubelet safely assesses exposed Kubelet interfaces (ports 10250 and 10255).
func (a *ContainerK8sAuditor) AuditKubelet(ctx context.Context, target ContainerTarget) (*ContainerAuditResult, error) {
	start := time.Now()
	res := &ContainerAuditResult{
		ID:             uuid.New().String(),
		Component:      ComponentKubelet,
		TargetURL:      sanitizeTargetURL(target.RawURL),
		SafeHeaders:    make(map[string]string),
		AuditTimestamp: time.Now().UTC(),
	}

	baseURL := strings.TrimRight(target.RawURL, "/")

	// Step 1: Probe /healthz
	healthURL := baseURL + "/healthz"
	reqHealth, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating Kubelet health request: %w", err)
	}
	reqHealth.Header.Set("User-Agent", a.options.UserAgent)

	respHealth, err := a.client.Do(reqHealth)
	if err != nil {
		res.Classification = ExposureNotReachable
		res.EvidenceSummary = fmt.Sprintf("Network connection to Kubelet failed: %v", err)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"
		res.AuditDuration = time.Since(start)
		return res, nil
	}
	defer respHealth.Body.Close()

	res.HTTPStatus = respHealth.StatusCode
	extractSafeResponseHeaders(respHealth.Header, res.SafeHeaders)
	bodyHealth, _ := readLimitedResponse(respHealth.Body, a.options.MaxResponseSize)

	if isGenericHTML(respHealth.Header, bodyHealth) {
		res.Classification = ExposureInconclusive
		res.EvidenceSummary = "Endpoint returned HTTP 200 with HTML web response; not a Kubelet interface"
		res.Severity = "INFO"
		res.Confidence = "LOW"
		res.AuditDuration = time.Since(start)
		return res, nil
	}

	healthOK := respHealth.StatusCode == http.StatusOK && strings.TrimSpace(string(bodyHealth)) == "ok"
	if healthOK {
		res.ServiceIdentified = true
		res.ServiceName = "Kubernetes Kubelet"
	}

	// Step 2: Probe /pods (Check for unauthenticated pod list disclosure)
	podsURL := baseURL + "/pods"
	reqPods, _ := http.NewRequestWithContext(ctx, http.MethodGet, podsURL, nil)
	reqPods.Header.Set("User-Agent", a.options.UserAgent)

	respPods, errPods := a.client.Do(reqPods)
	if errPods == nil {
		defer respPods.Body.Close()
		bodyPods, _ := readLimitedResponse(respPods.Body, a.options.MaxResponseSize)

		if respPods.StatusCode == http.StatusOK && !isGenericHTML(respPods.Header, bodyPods) {
			var podList struct {
				Kind  string `json:"kind"`
				Items []struct {
					Metadata struct {
						Name      string `json:"name"`
						Namespace string `json:"namespace"`
					} `json:"metadata"`
				} `json:"items"`
			}

			if json.Unmarshal(bodyPods, &podList) == nil && (podList.Kind == "PodList" || len(podList.Items) > 0) {
				// Section 3: Administrative access is NOT inferred from pod listing alone.
				// Pod listing proves unauthenticated workload information disclosure.
				res.ServiceIdentified = true
				res.ServiceName = "Kubernetes Kubelet"
				res.IsUnauthenticated = true
				res.IsAdminAccessible = false // Strictly accurate: read-only info disclosure verified, admin exec not inferred
				res.Classification = ExposureKubeletExposed
				res.EvidenceSummary = fmt.Sprintf("Unauthenticated Kubelet API on %s exposes active pod manifest list via /pods (%d pods listed). Discloses workload metadata and pod architecture; administrative command execution was not verified.", target.RawURL, len(podList.Items))
				res.Severity = "HIGH"
				res.Confidence = "CONFIRMED"
				res.Remediation = "Enforce --anonymous-auth=false on Kubelet and configure webhook authorization with the API server."
				res.AuditDuration = time.Since(start)
				res.Finding = res.ToFinding(target.RawURL)
				return res, nil
			}
		}

		if respPods.StatusCode == http.StatusUnauthorized || respPods.StatusCode == http.StatusForbidden {
			res.ServiceIdentified = true
			res.ServiceName = "Kubernetes Kubelet"
			res.IsAuthenticated = true
			if healthOK {
				res.Classification = ExposureServiceIdentified
				res.EvidenceSummary = fmt.Sprintf("Kubelet identified via /healthz on %s; pod listing and administrative endpoints require authentication (HTTP %d).", target.RawURL, respPods.StatusCode)
				res.Severity = "INFO"
				res.Confidence = "CONFIRMED"
			} else {
				res.Classification = ExposureAuthenticationRequired
				res.EvidenceSummary = fmt.Sprintf("Kubelet endpoint on %s requires authentication (HTTP %d).", target.RawURL, respPods.StatusCode)
				res.Severity = "INFO"
				res.Confidence = "CONFIRMED"
			}
			res.AuditDuration = time.Since(start)
			return res, nil
		}
	}

	if healthOK {
		res.Classification = ExposureServiceIdentified
		res.EvidenceSummary = fmt.Sprintf("Kubelet health endpoint (/healthz) responded with 'ok' on %s; administrative endpoints are not accessible.", target.RawURL)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"
		res.AuditDuration = time.Since(start)
		return res, nil
	}

	res.Classification = ExposureInconclusive
	res.EvidenceSummary = fmt.Sprintf("Endpoint %s responded with status %d but did not match Kubelet signatures", target.RawURL, respHealth.StatusCode)
	res.Severity = "INFO"
	res.Confidence = "LOW"
	res.AuditDuration = time.Since(start)
	return res, nil
}

// -------------------------------------------------------------------------
// 4. etcd Exposure Auditor (Section 4)
// -------------------------------------------------------------------------

// AuditEtcd safely assesses exposed etcd key-value store interfaces (ports 2379, 2380).
func (a *ContainerK8sAuditor) AuditEtcd(ctx context.Context, target ContainerTarget) (*ContainerAuditResult, error) {
	start := time.Now()
	res := &ContainerAuditResult{
		ID:             uuid.New().String(),
		Component:      ComponentEtcd,
		TargetURL:      sanitizeTargetURL(target.RawURL),
		SafeHeaders:    make(map[string]string),
		AuditTimestamp: time.Now().UTC(),
	}

	baseURL := strings.TrimRight(target.RawURL, "/")

	// Step 1: Probe /health
	healthOK := false
	healthURL := baseURL + "/health"
	reqHealth, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	reqHealth.Header.Set("User-Agent", a.options.UserAgent)
	if respHealth, errH := a.client.Do(reqHealth); errH == nil {
		defer respHealth.Body.Close()
		bodyHealth, _ := readLimitedResponse(respHealth.Body, a.options.MaxResponseSize)
		var hDoc struct {
			Health string `json:"health"`
		}
		if respHealth.StatusCode == http.StatusOK && json.Unmarshal(bodyHealth, &hDoc) == nil && (hDoc.Health == "true" || hDoc.Health == "ok") {
			healthOK = true
			res.ServiceIdentified = true
			res.ServiceName = "etcd Distributed Key-Value Store"
		}
	}

	// Step 2: Probe /version
	versionURL := baseURL + "/version"
	reqVer, err := http.NewRequestWithContext(ctx, http.MethodGet, versionURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating etcd version request: %w", err)
	}
	reqVer.Header.Set("User-Agent", a.options.UserAgent)

	respVer, err := a.client.Do(reqVer)
	if err != nil {
		if healthOK {
			res.Classification = ExposureServiceIdentified
			res.EvidenceSummary = fmt.Sprintf("etcd health endpoint (/health) reachable on %s; key-value datastore was not accessed or queried.", target.RawURL)
			res.Severity = "INFO"
			res.Confidence = "CONFIRMED"
			res.AuditDuration = time.Since(start)
			return res, nil
		}
		res.Classification = ExposureNotReachable
		res.EvidenceSummary = fmt.Sprintf("Network connection to etcd failed: %v", err)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"
		res.AuditDuration = time.Since(start)
		return res, nil
	}
	defer respVer.Body.Close()

	res.HTTPStatus = respVer.StatusCode
	extractSafeResponseHeaders(respVer.Header, res.SafeHeaders)
	bodyVer, _ := readLimitedResponse(respVer.Body, a.options.MaxResponseSize)

	if isGenericHTML(respVer.Header, bodyVer) {
		res.Classification = ExposureInconclusive
		res.EvidenceSummary = "Endpoint returned HTTP 200 with HTML webpage; not an etcd cluster endpoint"
		res.Severity = "INFO"
		res.Confidence = "LOW"
		res.AuditDuration = time.Since(start)
		return res, nil
	}

	var etcdDoc struct {
		EtcdServer  string `json:"etcdserver"`
		EtcdCluster string `json:"etcdcluster"`
	}
	if respVer.StatusCode == http.StatusOK && json.Unmarshal(bodyVer, &etcdDoc) == nil && (etcdDoc.EtcdServer != "" || etcdDoc.EtcdCluster != "") {
		// Section 4: Public service / version information disclosure.
		// Never claim datastore access when only version information was returned.
		res.ServiceIdentified = true
		res.ServiceName = "etcd Distributed Key-Value Store"
		res.VersionDisclosed = etcdDoc.EtcdServer
		res.IsUnauthenticated = true
		res.Classification = ExposureEtcdExposed
		res.EvidenceSummary = fmt.Sprintf("etcd service on %s discloses server version (%s) via /version. Read-only information disclosure; key-value datastore was not accessed or queried.", target.RawURL, etcdDoc.EtcdServer)
		res.Severity = "MEDIUM"
		res.Confidence = "CONFIRMED"
		res.Remediation = "Enable client certificate authentication (--client-cert-auth=true) and restrict network access to etcd."
		res.AuditDuration = time.Since(start)
		res.Finding = res.ToFinding(target.RawURL)
		return res, nil
	}

	if healthOK {
		res.Classification = ExposureServiceIdentified
		res.EvidenceSummary = fmt.Sprintf("etcd health endpoint (/health) reachable on %s; key-value datastore was not accessed or queried.", target.RawURL)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"
		res.AuditDuration = time.Since(start)
		return res, nil
	}

	if respVer.StatusCode == http.StatusUnauthorized || respVer.StatusCode == http.StatusForbidden {
		res.ServiceIdentified = true
		res.ServiceName = "etcd Distributed Key-Value Store"
		res.IsAuthenticated = true
		res.Classification = ExposureAuthenticationRequired
		res.EvidenceSummary = fmt.Sprintf("etcd endpoint on %s requires authentication (HTTP %d).", target.RawURL, respVer.StatusCode)
		res.Severity = "INFO"
		res.Confidence = "CONFIRMED"
		res.AuditDuration = time.Since(start)
		return res, nil
	}

	res.Classification = ExposureInconclusive
	res.EvidenceSummary = fmt.Sprintf("Endpoint %s responded with status %d but did not match etcd signatures", target.RawURL, respVer.StatusCode)
	res.Severity = "INFO"
	res.Confidence = "LOW"
	res.AuditDuration = time.Since(start)
	return res, nil
}

// -------------------------------------------------------------------------
// 5. Kubernetes Dashboard & Management Interfaces Auditor (Section 5)
// -------------------------------------------------------------------------

// AuditDashboard safely verifies exposed cluster dashboards (K8s Dashboard, Portainer).
func (a *ContainerK8sAuditor) AuditDashboard(ctx context.Context, target ContainerTarget) (*ContainerAuditResult, error) {
	start := time.Now()
	res := &ContainerAuditResult{
		ID:             uuid.New().String(),
		Component:      ComponentDashboard,
		TargetURL:      sanitizeTargetURL(target.RawURL),
		SafeHeaders:    make(map[string]string),
		AuditTimestamp: time.Now().UTC(),
	}

	baseURL := strings.TrimRight(target.RawURL, "/")

	// Candidate paths matching real supported Kubernetes Dashboard and Portainer routes
	candidatePaths := []string{
		"/",
		"/#/login",
		"/api/v1/overview",
		"/api/v1/login/status",
		"/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/",
		"/api/status",
		"/api/endpoints",
	}

	for _, p := range candidatePaths {
		checkURL := baseURL + p
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", a.options.UserAgent)

		resp, err := a.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		res.HTTPStatus = resp.StatusCode
		extractSafeResponseHeaders(resp.Header, res.SafeHeaders)
		body, _ := readLimitedResponse(resp.Body, a.options.MaxResponseSize)
		strBody := string(body)
		lowerBody := strings.ToLower(strBody)

		// False positive defense: skip generic HTML
		if isGenericHTML(resp.Header, body) && !strings.Contains(lowerBody, "kubernetes-dashboard") && !strings.Contains(lowerBody, "kubernetes dashboard") && !strings.Contains(lowerBody, "portainer") {
			continue
		}

		// 1. Kubernetes Dashboard Detection
		if strings.Contains(lowerBody, "kubernetes-dashboard") || strings.Contains(lowerBody, "kubernetes dashboard") || strings.Contains(lowerBody, "ng-app=\"kubernetesdashboard\"") || strings.Contains(lowerBody, "<kd-root") {
			res.ServiceIdentified = true
			res.ServiceName = "Kubernetes Dashboard"

			// Check if authentication redirect / login form is enforced
			if strings.Contains(lowerBody, "token") || strings.Contains(lowerBody, "kubeconfig") || strings.Contains(lowerBody, "sign in") || strings.Contains(lowerBody, "login") || resp.StatusCode == http.StatusUnauthorized || strings.Contains(lowerBody, "<kd-login") {
				res.IsAuthenticated = true
				res.Classification = ExposureAuthenticationRequired
				res.EvidenceSummary = fmt.Sprintf("Kubernetes Dashboard identified on %s; authentication prompt is enforced.", checkURL)
				res.Severity = "INFO"
				res.Confidence = "CONFIRMED"
				res.AuditDuration = time.Since(start)
				return res, nil
			}

			// Unauthenticated dashboard access
			res.IsUnauthenticated = true
			res.IsAdminAccessible = true
			res.Classification = ExposureExposedManagementInterface
			res.EvidenceSummary = fmt.Sprintf("Exposed unauthenticated Kubernetes Dashboard on %s. Allows unauthorized inspection of cluster workloads.", checkURL)
			res.Severity = "HIGH"
			res.Confidence = "HIGH"
			res.Remediation = "Enforce token authentication or deploy Ingress with external identity provider (IdP) authentication."
			res.AuditDuration = time.Since(start)
			res.Finding = res.ToFinding(target.RawURL)
			return res, nil
		}

		// 2. Portainer Container Management Dashboard
		if strings.Contains(lowerBody, "portainer") || strings.Contains(strBody, "Portainer") {
			res.ServiceIdentified = true
			res.ServiceName = "Portainer Management Interface"

			// Check if /api/endpoints requires auth (401)
			if p == "/api/endpoints" && resp.StatusCode == http.StatusOK && strings.HasPrefix(strings.TrimSpace(strBody), "[") {
				res.IsUnauthenticated = true
				res.Classification = ExposureExposedManagementInterface
				res.EvidenceSummary = fmt.Sprintf("Exposed Portainer container management dashboard allows unauthenticated endpoint inspection on %s.", checkURL)
				res.Severity = "HIGH"
				res.Confidence = "HIGH"
				res.Remediation = "Enforce mandatory administrative credentials and disable public exposure of Portainer."
				res.AuditDuration = time.Since(start)
				res.Finding = res.ToFinding(target.RawURL)
				return res, nil
			}

			if resp.StatusCode == http.StatusUnauthorized || strings.Contains(lowerBody, "login") || strings.Contains(lowerBody, "authenticate") {
				res.IsAuthenticated = true
				res.Classification = ExposureAuthenticationRequired
				res.EvidenceSummary = fmt.Sprintf("Portainer interface identified on %s; authentication is enforced.", checkURL)
				res.Severity = "INFO"
				res.Confidence = "CONFIRMED"
				res.AuditDuration = time.Since(start)
				return res, nil
			}

			if p == "/api/status" && resp.StatusCode == http.StatusOK {
				// Probe /api/endpoints to verify whether management endpoint inspection is exposed
				reqEndpoints, errEP := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/endpoints", nil)
				if errEP == nil {
					reqEndpoints.Header.Set("User-Agent", a.options.UserAgent)
					if respEndpoints, errDo := a.client.Do(reqEndpoints); errDo == nil {
						defer respEndpoints.Body.Close()
						bodyEP, _ := readLimitedResponse(respEndpoints.Body, a.options.MaxResponseSize)
						if respEndpoints.StatusCode == http.StatusOK && strings.HasPrefix(strings.TrimSpace(string(bodyEP)), "[") {
							res.IsUnauthenticated = true
							res.Classification = ExposureExposedManagementInterface
							res.EvidenceSummary = fmt.Sprintf("Exposed Portainer container management dashboard allows unauthenticated endpoint inspection on %s.", baseURL+"/api/endpoints")
							res.Severity = "HIGH"
							res.Confidence = "HIGH"
							res.Remediation = "Enforce mandatory administrative credentials and disable public exposure of Portainer."
							res.AuditDuration = time.Since(start)
							res.Finding = res.ToFinding(target.RawURL)
							return res, nil
						}
					}
				}

				res.IsUnauthenticated = true
				res.Classification = ExposureUnauthenticatedInfoDisclosure
				res.EvidenceSummary = fmt.Sprintf("Portainer instance status and version disclosed via /api/status on %s.", checkURL)
				res.Severity = "LOW"
				res.Confidence = "CONFIRMED"
				res.AuditDuration = time.Since(start)
				res.Finding = res.ToFinding(target.RawURL)
				return res, nil
			}
		}
	}

	res.Classification = ExposureInconclusive
	res.EvidenceSummary = fmt.Sprintf("Endpoint %s did not match known Kubernetes or container management dashboard signatures", target.RawURL)
	res.Severity = "INFO"
	res.Confidence = "LOW"
	res.AuditDuration = time.Since(start)
	return res, nil
}

// -------------------------------------------------------------------------
// 6. Auto-Detection Dispatcher
// -------------------------------------------------------------------------

// AuditAutoDetect probes standard endpoints sequentially to identify component.
func (a *ContainerK8sAuditor) AuditAutoDetect(ctx context.Context, target ContainerTarget) (*ContainerAuditResult, error) {
	// Try Docker
	resDocker, err := a.AuditDocker(ctx, target)
	if err == nil && resDocker.ServiceIdentified && resDocker.Classification != ExposureInconclusive {
		return resDocker, nil
	}

	// Try Kubernetes API Server
	resK8s, err := a.AuditK8sAPI(ctx, target)
	if err == nil && resK8s.ServiceIdentified && resK8s.Classification != ExposureInconclusive {
		return resK8s, nil
	}

	// Try Kubelet
	resKubelet, err := a.AuditKubelet(ctx, target)
	if err == nil && resKubelet.ServiceIdentified && resKubelet.Classification != ExposureInconclusive {
		return resKubelet, nil
	}

	// Try etcd
	resEtcd, err := a.AuditEtcd(ctx, target)
	if err == nil && resEtcd.ServiceIdentified && resEtcd.Classification != ExposureInconclusive {
		return resEtcd, nil
	}

	// Try Dashboard
	resDash, err := a.AuditDashboard(ctx, target)
	if err == nil && resDash.ServiceIdentified && resDash.Classification != ExposureInconclusive {
		return resDash, nil
	}

	// Default fallback result
	return &ContainerAuditResult{
		ID:              uuid.New().String(),
		Component:       ComponentAutoDetect,
		TargetURL:       sanitizeTargetURL(target.RawURL),
		Classification:  ExposureInconclusive,
		EvidenceSummary: fmt.Sprintf("Endpoint %s is reachable but did not match recognized container or Kubernetes service signatures", target.RawURL),
		Severity:        "INFO",
		Confidence:      "LOW",
		AuditDuration:   time.Millisecond,
		AuditTimestamp:  time.Now().UTC(),
	}, nil
}

// -------------------------------------------------------------------------
// Batch Concurrency & Worker Pool
// -------------------------------------------------------------------------

// AuditBatch executes bounded concurrent audits across multiple container targets.
func (a *ContainerK8sAuditor) AuditBatch(ctx context.Context, targets []ContainerTarget, maxConcurrency int) ([]ContainerAuditResult, error) {
	if maxConcurrency <= 0 {
		maxConcurrency = 4
	}

	results := make([]ContainerAuditResult, len(targets))
	errCh := make(chan error, len(targets))
	targetCh := make(chan int, len(targets))

	var wg sync.WaitGroup
	workers := maxConcurrency
	if workers > len(targets) {
		workers = len(targets)
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range targetCh {
				select {
				case <-ctx.Done():
					return
				default:
					res, err := a.Audit(ctx, targets[idx])
					if err != nil {
						errCh <- fmt.Errorf("audit target %s: %w", targets[idx].RawURL, err)
						continue
					}
					if res != nil {
						results[idx] = *res
					}
				}
			}
		}()
	}

	for i := range targets {
		targetCh <- i
	}
	close(targetCh)
	wg.Wait()
	close(errCh)

	var firstErr error
	select {
	case err := <-errCh:
		firstErr = err
	default:
	}

	return results, firstErr
}

// -------------------------------------------------------------------------
// Finding Integration (Section 12)
// -------------------------------------------------------------------------

// ToFinding converts a ContainerAuditResult into a standardized FELIX report.Finding.
func (r *ContainerAuditResult) ToFinding(targetURL string) *report.Finding {
	// Only generate findings for actionable exposures or information disclosure
	if r.Classification == ExposureNotReachable || r.Classification == ExposureResourceNotFound || r.Classification == ExposureAccessDenied || r.Classification == ExposureInconclusive || r.Classification == ExposureAuthenticationRequired || r.Classification == ExposureServiceIdentified {
		return nil
	}

	findingID := computeDeterministicContainerFindingID(string(r.Component), r.ServiceName, string(r.Classification))
	title := fmt.Sprintf("[%s] %s Exposure: %s", r.Component, r.ServiceName, r.Classification)
	switch r.Classification {
	case ExposureUnauthenticatedManagementAccess:
		title = fmt.Sprintf("[%s] Unauthenticated Management Endpoint Accessible (%s)", r.Component, r.ServiceName)
	case ExposureUnauthenticatedDockerAPIExposed:
		title = fmt.Sprintf("[%s] Unauthenticated Docker Remote API Exposed Over TCP", r.Component)
	case ExposureAnonymousAPIDiscovery:
		title = fmt.Sprintf("[KUBERNETES] Anonymous API Discovery Exposed on API Server")
	case ExposureKubernetesAPIExposed:
		title = fmt.Sprintf("[KUBERNETES] Kubernetes API Server Exposed Without Authentication")
	case ExposureKubeletExposed:
		title = fmt.Sprintf("[KUBERNETES] Kubelet API Unauthenticated Pod Manifest Exposure")
	case ExposureEtcdExposed:
		title = fmt.Sprintf("[ETCD] etcd Service Version Disclosed Without Authentication")
	case ExposureExposedManagementInterface:
		title = fmt.Sprintf("[%s] Unauthenticated Management Dashboard Exposed (%s)", r.Component, r.ServiceName)
	case ExposureUnauthenticatedInfoDisclosure:
		title = fmt.Sprintf("[%s] Unauthenticated Information Disclosure (%s)", r.Component, r.ServiceName)
	}

	details := map[string]string{
		"component":           string(r.Component),
		"service_name":        r.ServiceName,
		"classification":      string(r.Classification),
		"version_disclosed":   r.VersionDisclosed,
		"is_unauthenticated":  fmt.Sprintf("%t", r.IsUnauthenticated),
		"is_admin_accessible": fmt.Sprintf("%t", r.IsAdminAccessible),
		"http_status":         fmt.Sprintf("%d", r.HTTPStatus),
		"audit_duration_ms":   fmt.Sprintf("%.2f", float64(r.AuditDuration.Nanoseconds())/1e6),
	}

	sanitizedTarget := sanitizeTargetURL(targetURL)

	f := &report.Finding{
		ID:          findingID,
		Title:       title,
		Description: r.EvidenceSummary,
		Severity:    r.Severity,
		Confidence:  r.Confidence,
		Category:    "CloudSec / Container & Kubernetes Exposure",
		Remediation: r.Remediation,
		Timestamp:   r.AuditTimestamp,
		Target:      sanitizedTarget,
		Endpoint:    sanitizedTarget,
		Method:      "CONTAINER_K8S_AUDIT",
		Evidence:    r.EvidenceSummary,
		EvidenceDetails: report.EvidenceDetails{
			Observation:     r.EvidenceSummary,
			Location:        sanitizedTarget,
			DetectionMethod: "CONTAINER_K8S_AUDITOR",
			Details:         details,
		},
	}
	return f
}

// -------------------------------------------------------------------------
// Helper Functions
// -------------------------------------------------------------------------

func readLimitedResponse(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = DefaultContainerMaxResponseSize
	}
	return io.ReadAll(io.LimitReader(r, limit))
}

func sanitizeTargetURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.User != nil {
		u.User = nil
	}
	return u.String()
}

func extractSafeResponseHeaders(src http.Header, dst map[string]string) {
	for k, v := range src {
		lower := strings.ToLower(k)
		if strings.HasPrefix(lower, "docker-") || strings.HasPrefix(lower, "api-version") || strings.HasPrefix(lower, "x-kubernetes-") || lower == "server" || lower == "content-type" || lower == "etag" {
			dst[k] = strings.Join(v, ", ")
		}
	}
}

func isGenericHTML(headers http.Header, body []byte) bool {
	ct := strings.ToLower(headers.Get("Content-Type"))
	if strings.Contains(ct, "text/html") {
		return true
	}
	preview := strings.ToLower(string(body[:minInt(len(body), 512)]))
	return strings.Contains(preview, "<!doctype html") || strings.Contains(preview, "<html") || strings.Contains(preview, "<head>")
}

func computeDeterministicContainerFindingID(component, service, classification string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", component, service, classification)))
	return hex.EncodeToString(h[:16])
}
