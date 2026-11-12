package browser

import "testing"

func TestPhase9_DefaultConfig_VerifiesTLSCerts(t *testing.T) {
	if DefaultConfig().IgnoreCertErrors {
		t.Errorf("expected browser.DefaultConfig().IgnoreCertErrors to be false by default")
	}
}
