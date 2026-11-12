package crawler

import (
	"net"
	"testing"
)

func TestPhase9_ProhibitedIPReason_ExtendedTransitionAndReservedRanges(t *testing.T) {
	blockedEvenWhenPrivateAllowed := []string{
		"64:ff9b::192.0.2.1",
		"64:ff9b:1::10.0.0.1",
		"2001::1",
		"2002:0a00:0001::1",
		"2001:db8::1",
		"100::1",
		"192.0.0.1",
		"192.0.2.1",
		"198.18.0.1",
		"198.51.100.1",
		"203.0.113.1",
		"240.0.0.1",
		"169.254.169.254",
		"fd00:ec2::254",
	}

	for _, ipStr := range blockedEvenWhenPrivateAllowed {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			t.Fatalf("failed to parse IP %q", ipStr)
		}
		if prohibited, _ := ProhibitedIPReason(ip, true, true); !prohibited {
			t.Errorf("expected %s to be unconditionally prohibited even with allowLoopback+allowPrivate", ipStr)
		}
	}

	if prohibited, reason := ProhibitedIPReason(net.ParseIP("93.184.216.34"), false, false); prohibited {
		t.Errorf("expected public IP 93.184.216.34 to be allowed, got reason=%s", reason)
	}
}
