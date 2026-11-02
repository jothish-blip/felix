package lab

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestContainerK8sMock_Docker_Handlers(t *testing.T) {
	mock := NewContainerK8sMock()
	defer mock.Close()

	// 1. Docker Exposed _ping
	resp, err := http.Get(mock.BuildURL("docker-exposed/_ping"))
	if err != nil {
		t.Fatalf("failed GET docker-exposed/_ping: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "OK" {
		t.Fatalf("expected OK, got %s", string(b))
	}

	// 2. Docker Exposed version
	respVer, err := http.Get(mock.BuildURL("docker-exposed/version"))
	if err != nil {
		t.Fatalf("failed GET docker-exposed/version: %v", err)
	}
	defer respVer.Body.Close()
	bVer, _ := io.ReadAll(respVer.Body)
	if !strings.Contains(string(bVer), "24.0.5") {
		t.Fatalf("expected version 24.0.5 in body: %s", string(bVer))
	}

	// 3. Docker Protected
	respProt, err := http.Get(mock.BuildURL("docker-protected/_ping"))
	if err != nil {
		t.Fatalf("failed GET docker-protected/_ping: %v", err)
	}
	defer respProt.Body.Close()
	if respProt.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", respProt.StatusCode)
	}
}

func TestContainerK8sMock_Kubernetes_Handlers(t *testing.T) {
	mock := NewContainerK8sMock()
	defer mock.Close()

	// 1. K8s Exposed /version
	respVer, err := http.Get(mock.BuildURL("k8s-exposed/version"))
	if err != nil {
		t.Fatalf("failed GET k8s-exposed/version: %v", err)
	}
	defer respVer.Body.Close()
	bVer, _ := io.ReadAll(respVer.Body)
	if !strings.Contains(string(bVer), "v1.28.2") {
		t.Fatalf("expected v1.28.2 in body: %s", string(bVer))
	}

	// 2. K8s Exposed /api
	respAPI, err := http.Get(mock.BuildURL("k8s-exposed/api"))
	if err != nil {
		t.Fatalf("failed GET k8s-exposed/api: %v", err)
	}
	defer respAPI.Body.Close()
	bAPI, _ := io.ReadAll(respAPI.Body)
	if !strings.Contains(string(bAPI), "APIVersions") {
		t.Fatalf("expected APIVersions in body: %s", string(bAPI))
	}

	// 3. K8s Protected /api
	respProt, err := http.Get(mock.BuildURL("k8s-protected/api"))
	if err != nil {
		t.Fatalf("failed GET k8s-protected/api: %v", err)
	}
	defer respProt.Body.Close()
	if respProt.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", respProt.StatusCode)
	}
}

func TestContainerK8sMock_Kubelet_And_Etcd_Handlers(t *testing.T) {
	mock := NewContainerK8sMock()
	defer mock.Close()

	// 1. Kubelet Exposed /pods
	respPods, err := http.Get(mock.BuildURL("kubelet-exposed/pods"))
	if err != nil {
		t.Fatalf("failed GET kubelet-exposed/pods: %v", err)
	}
	defer respPods.Body.Close()
	bPods, _ := io.ReadAll(respPods.Body)
	if !strings.Contains(string(bPods), "PodList") {
		t.Fatalf("expected PodList in body: %s", string(bPods))
	}

	// 2. etcd Exposed /version
	respEtcd, err := http.Get(mock.BuildURL("etcd-exposed/version"))
	if err != nil {
		t.Fatalf("failed GET etcd-exposed/version: %v", err)
	}
	defer respEtcd.Body.Close()
	bEtcd, _ := io.ReadAll(respEtcd.Body)
	if !strings.Contains(string(bEtcd), "3.5.9") {
		t.Fatalf("expected 3.5.9 in body: %s", string(bEtcd))
	}

	// 3. Dashboard Exposed
	respDash, err := http.Get(mock.BuildURL("dashboard-exposed/"))
	if err != nil {
		t.Fatalf("failed GET dashboard-exposed: %v", err)
	}
	defer respDash.Body.Close()
	bDash, _ := io.ReadAll(respDash.Body)
	if !strings.Contains(string(bDash), "Kubernetes Dashboard") {
		t.Fatalf("expected Kubernetes Dashboard in body: %s", string(bDash))
	}
}
