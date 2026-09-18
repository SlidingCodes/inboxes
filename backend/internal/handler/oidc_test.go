package handler

import "testing"

// --- sanitizeNextPath ---
// This is the open-redirect guard on the OIDC callback: it must reject
// anything that isn't a same-origin relative path, since it comes back off
// a cookie an attacker could have set before the redirect round trip.

func TestSanitizeNextPath_ValidRelative(t *testing.T) {
	t.Parallel()
	if got := sanitizeNextPath("/d/thread/123"); got != "/d/thread/123" {
		t.Errorf("sanitizeNextPath: got %q, want unchanged", got)
	}
}

func TestSanitizeNextPath_Empty(t *testing.T) {
	t.Parallel()
	if got := sanitizeNextPath(""); got != "" {
		t.Errorf("sanitizeNextPath(empty): got %q, want empty", got)
	}
}

func TestSanitizeNextPath_ProtocolRelative(t *testing.T) {
	t.Parallel()
	// "//evil.com" is browser-interpreted as a scheme-relative absolute URL.
	if got := sanitizeNextPath("//evil.com"); got != "" {
		t.Errorf("sanitizeNextPath(//evil.com): got %q, want empty", got)
	}
}

func TestSanitizeNextPath_BackslashEscape(t *testing.T) {
	t.Parallel()
	// Browsers normalize "/\evil.com" to "//evil.com".
	if got := sanitizeNextPath("/\\evil.com"); got != "" {
		t.Errorf("sanitizeNextPath(/\\evil.com): got %q, want empty", got)
	}
}

func TestSanitizeNextPath_AbsoluteURL(t *testing.T) {
	t.Parallel()
	if got := sanitizeNextPath("https://evil.com"); got != "" {
		t.Errorf("sanitizeNextPath(absolute url): got %q, want empty", got)
	}
}

func TestSanitizeNextPath_NoLeadingSlash(t *testing.T) {
	t.Parallel()
	if got := sanitizeNextPath("evil.com"); got != "" {
		t.Errorf("sanitizeNextPath(no leading slash): got %q, want empty", got)
	}
}
