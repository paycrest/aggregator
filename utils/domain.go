package utils

import (
	"net/url"
	"strings"
)

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

func ExtractDomainFromRequest(origin, referer string) (string, error) {
	if origin != "" {
		return ExtractDomainFromOrigin(origin)
	}

	if referer != "" {
		return ExtractDomainFromReferer(referer)
	}

	return "", nil
}

func NormalizeDomain(domain string) string {
	if domain == "" {
		return ""
	}

	domain = strings.ToLower(domain)
	if strings.HasPrefix(domain, "www.") {
		domain = domain[4:]
	}

	return domain
}

func IsSubdomain(domain, parentDomain string) bool {
	if domain == "" || parentDomain == "" {
		return false
	}

	normalizedDomain := NormalizeDomain(domain)
	normalizedParent := NormalizeDomain(parentDomain)

	return strings.HasSuffix(normalizedDomain, "."+normalizedParent) || normalizedDomain == normalizedParent
}

func IsDomainAllowed(requestDomain string, whitelist []string) bool {
	if len(whitelist) == 0 {
		return true
	}

	if requestDomain == "" {
		return true
	}

	normalizedRequestDomain := NormalizeDomain(requestDomain)

	for _, allowedDomain := range whitelist {
		normalizedAllowedDomain := NormalizeDomain(allowedDomain)

		if normalizedRequestDomain == normalizedAllowedDomain {
			return true
		}
		if IsSubdomain(normalizedRequestDomain, normalizedAllowedDomain) {
			return true
		}
	}

	return false
}
