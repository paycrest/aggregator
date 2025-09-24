package utils

import (
	"net/url"
	"regexp"
	"strings"
)

// ExtractDomainFromOrigin extracts the domain from Origin header
func ExtractDomainFromOrigin(origin string) (string, error) {
	if origin == "" {
		return "", nil
	}
	
	parsedURL, err := url.Parse(origin)
	if err != nil {
		return "", err
	}
	
	return parsedURL.Host, nil
}

// ExtractDomainFromReferer extracts the domain from Referer header
func ExtractDomainFromReferer(referer string) (string, error) {
	if referer == "" {
		return "", nil
	}
	
	parsedURL, err := url.Parse(referer)
	if err != nil {
		return "", err
	}
	
	return parsedURL.Host, nil
}

// ExtractDomainFromRequest extracts domain from Origin or Referer headers
func ExtractDomainFromRequest(origin, referer string) (string, error) {
	// Prefer Origin header over Referer
	if origin != "" {
		return ExtractDomainFromOrigin(origin)
	}
	
	if referer != "" {
		return ExtractDomainFromReferer(referer)
	}
	
	return "", nil
}

// NormalizeDomain normalizes domain for comparison (removes www, converts to lowercase)
func NormalizeDomain(domain string) string {
	if domain == "" {
		return ""
	}
	
	// Convert to lowercase
	domain = strings.ToLower(domain)
	
	// Remove www prefix
	if strings.HasPrefix(domain, "www.") {
		domain = domain[4:]
	}
	
	return domain
}

// IsSubdomain checks if the given domain is a subdomain of the parent domain
func IsSubdomain(domain, parentDomain string) bool {
	if domain == "" || parentDomain == "" {
		return false
	}
	
	normalizedDomain := NormalizeDomain(domain)
	normalizedParent := NormalizeDomain(parentDomain)
	
	// Check if domain ends with parent domain
	return strings.HasSuffix(normalizedDomain, "."+normalizedParent) || normalizedDomain == normalizedParent
}

// IsDomainAllowed checks if a domain is allowed based on whitelist
func IsDomainAllowed(requestDomain string, whitelist []string) bool {
	if len(whitelist) == 0 {
		// Empty whitelist allows all domains (backward compatibility)
		return true
	}
	
	if requestDomain == "" {
		// No domain provided - allow for backward compatibility
		return true
	}
	
	normalizedRequestDomain := NormalizeDomain(requestDomain)
	
	for _, allowedDomain := range whitelist {
		normalizedAllowedDomain := NormalizeDomain(allowedDomain)
		
		// Exact match
		if normalizedRequestDomain == normalizedAllowedDomain {
			return true
		}
		
		// Subdomain match
		if IsSubdomain(normalizedRequestDomain, normalizedAllowedDomain) {
			return true
		}
	}
	
	return false
}

// ValidateDomainFormat validates if a domain has proper format
func ValidateDomainFormat(domain string) bool {
	if domain == "" {
		return false
	}
	
	// Basic domain validation regex
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	return domainRegex.MatchString(domain)
}
