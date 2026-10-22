package sessionsec

import (
	"strings"
	"testing"
)

func FuzzSplitSetCookieHeader(f *testing.F) {
	// Seed corpus
	f.Add("session=abc123; Path=/; Secure; HttpOnly")
	f.Add("session=abc123; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/, theme=dark; Path=/")
	f.Add("a=1, b=2, c=3")
	f.Add("name=val; expires=Thu, 01-Jan-1970 00:00:00 GMT, token=xyz")
	f.Add("")
	f.Add("   ")
	f.Add(",,,,")
	f.Add(";;;;")
	f.Add("single_token_without_equal")
	f.Add(strings.Repeat("a=b; ", 100))

	f.Fuzz(func(t *testing.T, header string) {
		cookies := SplitSetCookieHeader(header)
		// Invariant: SplitSetCookieHeader must never panic
		for _, c := range cookies {
			if strings.TrimSpace(c) == "" {
				t.Fatalf("SplitSetCookieHeader returned empty cookie string element")
			}
		}
	})
}

func FuzzParseSetCookie(f *testing.F) {
	// Seed corpus
	f.Add("session_id=s%3A12345; Path=/; Domain=.example.com; Secure; HttpOnly; SameSite=Strict; Max-Age=3600; Partitioned")
	f.Add("__Host-token=secret; Path=/; Secure; HttpOnly; SameSite=Lax")
	f.Add("__Secure-jwt=ey...; Path=/api; Secure; HttpOnly")
	f.Add("csrf_token=tok123; SameSite=None; Secure")
	f.Add("simple=val")
	f.Add("name=value; invalid_attr=1; =broken; empty_attr")
	f.Add("name=value; max-age=-1")
	f.Add("name=value; max-age=99999999999999999999")
	f.Add("name=value; max-age=notanumber")
	f.Add("name=value; samesite=unknown_value")
	f.Add("name=value; expires=invalid-date")
	f.Add("")
	f.Add("   ")
	f.Add("=onlyvalue")
	f.Add("onlyname=")
	f.Add("; ; ;")
	f.Add("name=\x00\x01\x02; Secure")

	f.Fuzz(func(t *testing.T, raw string) {
		cookie, err := ParseSetCookie(raw)
		if err != nil {
			return
		}

		// Invariant 1: Parsed cookie must have non-empty name
		if strings.TrimSpace(cookie.Name) == "" {
			t.Fatalf("ParseSetCookie succeeded but Name is empty for input %q", raw)
		}

		// Invariant 2: Parsed cookie Raw must be non-empty
		if cookie.Raw == "" {
			t.Fatalf("ParseSetCookie succeeded but Raw is empty for input %q", raw)
		}

		// Invariant 3: ClassifyCookie must never panic on the parsed cookie name
		cType := ClassifyCookie(cookie.Name)
		_ = cType
	})
}
