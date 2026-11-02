package lab

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
)

// ContainerK8sMock simulates Docker, Kubernetes, Kubelet, etcd, and dashboard endpoints on loopback.
type ContainerK8sMock struct {
	Server *httptest.Server
	URL    string
}

// NewContainerK8sMock creates and starts a deterministic local mock server for container & K8s auditing.
func NewContainerK8sMock() *ContainerK8sMock {
	m := &ContainerK8sMock{}
	mux := http.NewServeMux()

	// -------------------------------------------------------------------------
	// 1. Docker Endpoints
	// -------------------------------------------------------------------------

	// A. Docker Exposed _ping only
	mux.HandleFunc("/docker-ping-only/_ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("API-Version", "1.43")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// B. Docker Exposed version only
	mux.HandleFunc("/docker-version-only/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("API-Version", "1.43")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Version":"24.0.5","ApiVersion":"1.43","GitCommit":"ced0996","Os":"linux","Arch":"amd64"}`))
	})

	// C. Exposed Unauthenticated Docker Engine (_ping + version)
	mux.HandleFunc("/docker-exposed/_ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("API-Version", "1.43")
		w.Header().Set("Docker-Experimental", "false")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("/docker-exposed/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("API-Version", "1.43")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"Version": "24.0.5",
			"ApiVersion": "1.43",
			"MinAPIVersion": "1.12",
			"GitCommit": "ced0996",
			"GoVersion": "go1.20.6",
			"Os": "linux",
			"Arch": "amd64",
			"Components": [
				{"Name": "Engine", "Version": "24.0.5"},
				{"Name": "containerd", "Version": "v1.7.2"},
				{"Name": "runc", "Version": "v1.1.8"}
			]
		}`))
	})

	// D. Exposed Docker /info (Administrative Status Management Access)
	mux.HandleFunc("/docker-info-exposed/_ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("/docker-info-exposed/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Version":"24.0.5","ApiVersion":"1.43"}`))
	})
	mux.HandleFunc("/docker-info-exposed/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ID":"daemon-01","Containers":5,"Images":10,"ServerVersion":"24.0.5"}`))
	})

	// E. Protected Docker Engine (Requires mTLS or Auth)
	mux.HandleFunc("/docker-protected/_ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"client certificate required or unauthorized"}`))
	})
	mux.HandleFunc("/docker-protected/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
	})
	mux.HandleFunc("/docker-protected/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
	})

	// -------------------------------------------------------------------------
	// 2. Kubernetes API Server Endpoints
	// -------------------------------------------------------------------------

	// A. Publicly Reachable Unauthenticated K8s API Server (Admin /api/v1/namespaces open)
	mux.HandleFunc("/k8s-admin/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"major":"1","minor":"28","gitVersion":"v1.28.2","platform":"linux/amd64"}`))
	})
	mux.HandleFunc("/k8s-admin/api", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"kind":"APIVersions","versions":["v1"]}`))
	})
	mux.HandleFunc("/k8s-admin/api/v1/namespaces", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"kind":"NamespaceList","apiVersion":"v1","items":[{"metadata":{"name":"default"}},{"metadata":{"name":"kube-system"}}]}`))
	})
	mux.HandleFunc("/k8s-admin/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// B. Mixed Kubernetes Server (Discovery Open, Admin Protected)
	mux.HandleFunc("/k8s-mixed/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"major":"1","minor":"28","gitVersion":"v1.28.2","platform":"linux/amd64"}`))
	})
	mux.HandleFunc("/k8s-mixed/api", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"kind":"APIVersions","versions":["v1"]}`))
	})
	mux.HandleFunc("/k8s-mixed/api/v1/namespaces", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"kind":"Status","status":"Failure","message":"Unauthorized","code":401}`))
	})
	mux.HandleFunc("/k8s-mixed/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// C. Publicly Reachable K8s API Server (/version and /api open)
	mux.HandleFunc("/k8s-exposed/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"major": "1",
			"minor": "28",
			"gitVersion": "v1.28.2",
			"gitCommit": "89a4ea3e1e4ddd794657b77423f6ed72d",
			"platform": "linux/amd64"
		}`))
	})
	mux.HandleFunc("/k8s-exposed/api", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"kind": "APIVersions",
			"versions": ["v1"],
			"serverAddressByClientCIDRs": [{"clientCIDR": "0.0.0.0/0", "serverAddress": "10.0.0.1:6443"}]
		}`))
	})
	mux.HandleFunc("/k8s-exposed/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// D. Protected K8s API Server (Auth Required)
	mux.HandleFunc("/k8s-protected/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"major":"1","minor":"28","gitVersion":"v1.28.2","platform":"linux/amd64"}`))
	})
	mux.HandleFunc("/k8s-protected/api", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{
			"kind": "Status",
			"apiVersion": "v1",
			"metadata": {},
			"status": "Failure",
			"message": "Unauthorized",
			"reason": "Unauthorized",
			"code": 401
		}`))
	})

	// E. Version-Only K8s API Server
	mux.HandleFunc("/k8s-version-only/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"major":"1","minor":"28","gitVersion":"v1.28.2","platform":"linux/amd64"}`))
	})
	mux.HandleFunc("/k8s-version-only/api", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"kind":"Status","status":"Failure","reason":"Unauthorized","code":401}`))
	})

	// F. Anonymous Health-Only K8s API Server (/healthz ok, /api and /version require auth)
	mux.HandleFunc("/k8s-healthonly/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/k8s-healthonly/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"kind":"Status","status":"Failure","reason":"Unauthorized","code":401}`))
	})
	mux.HandleFunc("/k8s-healthonly/api", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"kind":"Status","status":"Failure","reason":"Unauthorized","code":401}`))
	})

	// G. Access Denied (system:anonymous rejected)
	mux.HandleFunc("/k8s-forbidden/api", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{
			"kind": "Status",
			"status": "Failure",
			"message": "User \"system:anonymous\" cannot get path \"/api\"",
			"reason": "Forbidden",
			"code": 403
		}`))
	})

	// -------------------------------------------------------------------------
	// 3. Kubelet Endpoints
	// -------------------------------------------------------------------------

	// A. Health-Only Kubelet
	mux.HandleFunc("/kubelet-healthonly/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/kubelet-healthonly/pods", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Unauthorized\n"))
	})

	// B. Exposed Kubelet (Unauthenticated /pods exposed)
	mux.HandleFunc("/kubelet-exposed/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/kubelet-exposed/pods", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"kind": "PodList",
			"apiVersion": "v1",
			"items": [
				{"metadata": {"name": "coredns-7744", "namespace": "kube-system"}},
				{"metadata": {"name": "payment-api-55bf", "namespace": "production"}}
			]
		}`))
	})

	// C. Protected Kubelet (10250 Auth Required)
	mux.HandleFunc("/kubelet-protected/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/kubelet-protected/pods", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Unauthorized\n"))
	})

	// -------------------------------------------------------------------------
	// 4. etcd Endpoints
	// -------------------------------------------------------------------------

	// A. Health-Only etcd
	mux.HandleFunc("/etcd-healthonly/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"health":"true"}`))
	})

	// B. Exposed etcd (/version disclosed)
	mux.HandleFunc("/etcd-exposed/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}`))
	})
	mux.HandleFunc("/etcd-exposed/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"health":"true"}`))
	})

	// C. Protected etcd
	mux.HandleFunc("/etcd-protected/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
	})

	// -------------------------------------------------------------------------
	// 5. Dashboards & Management Interfaces
	// -------------------------------------------------------------------------

	// A. Exposed Unauthenticated Kubernetes Dashboard
	mux.HandleFunc("/dashboard-exposed/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html>
<html>
<head><title>Kubernetes Dashboard</title></head>
<body>
<div class="kubernetes-dashboard-content">
<h1>Cluster Workloads</h1>
</div>
</body>
</html>`))
	})

	// B. Protected Kubernetes Dashboard (Requires Token / Sign-In)
	mux.HandleFunc("/dashboard-protected/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html>
<html>
<head><title>Kubernetes Dashboard Login</title></head>
<body>
<form>
<h2>Sign in to Kubernetes Dashboard</h2>
<label>Token</label><input type="password" name="token">
<label>Kubeconfig</label><input type="file" name="kubeconfig">
<button type="submit">Sign in</button>
</form>
</body>
</html>`))
	})

	// C. Exposed Portainer Dashboard (/api/endpoints open)
	mux.HandleFunc("/portainer-exposed/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Version":"2.19.1","InstanceID":"inst-01","Portainer":true}`))
	})
	mux.HandleFunc("/portainer-exposed/api/endpoints", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"Id":1,"Name":"primary-cluster","URL":"tcp://10.0.0.1:2375"}]`))
	})

	// D. Status-Only Portainer Dashboard (/api/status open, endpoints protected)
	mux.HandleFunc("/portainer-statusonly/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Version":"2.19.1","InstanceID":"inst-01","Portainer":true}`))
	})
	mux.HandleFunc("/portainer-statusonly/api/endpoints", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Unauthorized"}`))
	})

	// E. Protected Portainer
	mux.HandleFunc("/portainer-protected/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Server", "Portainer")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Unauthorized","service":"Portainer"}`))
	})
	mux.HandleFunc("/portainer-protected/api/endpoints", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Server", "Portainer")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Unauthorized","service":"Portainer"}`))
	})

	// -------------------------------------------------------------------------
	// 6. False-Positive, Security, and Error Scenarios
	// -------------------------------------------------------------------------

	// A. Generic HTML 200 (False Positive Catch-All)
	mux.HandleFunc("/falsepositive-html/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><html><head><title>Welcome</title></head><body><h1>Welcome to our corporate website</h1></body></html>`))
	})

	// B. SSRF Redirect to Cloud Metadata Service
	mux.HandleFunc("/redirect-ssrf/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	})

	// C. Redirect Loop
	mux.HandleFunc("/redirect-loop-a/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/redirect-loop-b/", http.StatusFound)
	})
	mux.HandleFunc("/redirect-loop-b/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/redirect-loop-a/", http.StatusFound)
	})

	// D. Large Payload (> 2 MB)
	mux.HandleFunc("/large-payload/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		chunk := strings.Repeat("A", 64*1024) // 64 KB
		for i := 0; i < 35; i++ {             // ~2.24 MB
			_, _ = w.Write([]byte(chunk))
		}
	})

	m.Server = httptest.NewServer(mux)
	m.URL = m.Server.URL
	return m
}

// Close terminates the mock server.
func (m *ContainerK8sMock) Close() {
	if m.Server != nil {
		m.Server.Close()
	}
}

// BuildURL constructs a full URL pointing to a mock path.
func (m *ContainerK8sMock) BuildURL(path string) string {
	cleanPath := strings.TrimLeft(path, "/")
	return fmt.Sprintf("%s/%s", m.URL, cleanPath)
}
