package utils

import (
	"net/url"
	"strings"
)

// ExtractRequestDomain returns the host (domain) from the request's Origin or Referer header.
// Prefers Origin, falls back to Referer. Returns empty string if neither is present or parseable.
func ExtractRequestDomain(origin, referer string) string {
	if origin != "" {
		if host := hostFromURL(origin); host != "" {
			return host
		}
	}
	if referer != "" {
		if host := hostFromURL(referer); host != "" {
			return host
		}
	}
	return ""
}

// Returns empty string on parse error.
func hostFromURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	// Ensure scheme for url.Parse
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(u.Hostname()))
}

// IsDomainAllowed checks if requestHost is allowed by whitelist.
// - Empty whitelist: allow any domain (backward compatibility).
// - Exact match: requestHost equals a whitelist entry (normalized lowercase).
// - Subdomain match: requestHost is a subdomain of a whitelist entry (e.g. "app.example.com" matches "example.com").
func IsDomainAllowed(requestHost string, whitelist []string) bool {
	if len(whitelist) == 0 {
		return true
	}
	requestHost = strings.ToLower(strings.TrimSpace(requestHost))
	if requestHost == "" {
		return false
	}
	for _, allowed := range whitelist {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		if allowed == "" {
			continue
		}
		if requestHost == allowed {
			return true
		}
		// Subdomain: requestHost must end with "."+allowed
		if strings.HasSuffix(requestHost, "."+allowed) {
			return true
		}
	}
	return false
}
