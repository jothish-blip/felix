package auth

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestPhase9_DefaultTLSVerification_Enforced(t *testing.T) {
	tr, err := NewAuthenticatedTransport(AuthenticatedTransportOptions{
		TargetURL: "https://app.authorized.example",
	})
	if err != nil {
		t.Fatalf("NewAuthenticatedTransport failed: %v", err)
	}
	baseHTTP, ok := tr.base.(*http.Transport)
	if !ok || baseHTTP.TLSClientConfig == nil {
		t.Fatalf("expected *http.Transport with non-nil TLSClientConfig")
	}
	if baseHTTP.TLSClientConfig.InsecureSkipVerify {
		t.Errorf("expected default AuthenticatedTransport to verify TLS certificates (InsecureSkipVerify=false)")
	}
	if baseHTTP.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("expected MinVersion >= TLS 1.2, got %d", baseHTTP.TLSClientConfig.MinVersion)
	}

	mgr, err := NewIdentityManager(IdentityManagerOptions{
		TargetURL: "https://app.authorized.example",
	})
	if err != nil {
		t.Fatalf("NewIdentityManager failed: %v", err)
	}
	mgrHTTP := mgr.Transport().base.(*http.Transport)
	if mgrHTTP.TLSClientConfig.InsecureSkipVerify {
		t.Errorf("expected default IdentityManager to verify TLS certificates (InsecureSkipVerify=false)")
	}
}
