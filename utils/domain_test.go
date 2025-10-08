package utils

import (
	"testing"
)

func TestExtractDomainFromOrigin(t *testing.T) {
	tests := []struct {
		name     string
		origin   string
		expected string
		hasError bool
	}{
		{
			name:     "Valid HTTPS origin",
			origin:   "https://example.com",
			expected: "example.com",
			hasError: false,
		},
		{
			name:     "Valid HTTP origin",
			origin:   "http://localhost:3000",
			expected: "localhost:3000",
			hasError: false,
		},
		{
			name:     "Origin with path",
			origin:   "https://example.com/path",
			expected: "example.com",
			hasError: false,
		},
		{
			name:     "Empty origin",
			origin:   "",
			expected: "",
			hasError: false,
		},
		{
			name:     "Invalid origin",
			origin:   "://invalid",
			expected: "",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ExtractDomainFromOrigin(tt.origin)

			if tt.hasError && err == nil {
				t.Errorf("Expected error but got none")
			}

			if !tt.hasError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{
			name:     "Domain with www",
			domain:   "www.example.com",
			expected: "example.com",
		},
		{
			name:     "Domain without www",
			domain:   "example.com",
			expected: "example.com",
		},
		{
			name:     "Uppercase domain",
			domain:   "EXAMPLE.COM",
			expected: "example.com",
		},
		{
			name:     "Empty domain",
			domain:   "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestIsDomainAllowed(t *testing.T) {
	tests := []struct {
		name          string
		requestDomain string
		whitelist     []string
		expected      bool
	}{
		{
			name:          "Empty whitelist allows all",
			requestDomain: "example.com",
			whitelist:     []string{},
			expected:      true,
		},
		{
			name:          "Exact match",
			requestDomain: "example.com",
			whitelist:     []string{"example.com"},
			expected:      true,
		},
		{
			name:          "Subdomain match",
			requestDomain: "api.example.com",
			whitelist:     []string{"example.com"},
			expected:      true,
		},
		{
			name:          "No match",
			requestDomain: "other.com",
			whitelist:     []string{"example.com"},
			expected:      false,
		},
		{
			name:          "Case insensitive",
			requestDomain: "EXAMPLE.COM",
			whitelist:     []string{"example.com"},
			expected:      true,
		},
		{
			name:          "WWW normalization",
			requestDomain: "www.example.com",
			whitelist:     []string{"example.com"},
			expected:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsDomainAllowed(tt.requestDomain, tt.whitelist)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}
