package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractRequestDomain(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		referer string
		want   string
	}{
		{
			name:   "empty both",
			origin: "",
			referer: "",
			want:   "",
		},
		{
			name:   "origin with https",
			origin: "https://app.example.com/path",
			referer: "",
			want:   "app.example.com",
		},
		{
			name:   "origin with http and port",
			origin: "http://localhost:3000",
			referer: "",
			want:   "localhost",
		},
		{
			name:   "origin preferred over referer",
			origin: "https://origin.example.com",
			referer: "https://referer.example.com",
			want:   "origin.example.com",
		},
		{
			name:   "fallback to referer when origin empty",
			origin: "",
			referer: "https://referer.example.com/foo?q=1",
			want:   "referer.example.com",
		},
		{
			name:   "invalid origin fallback to referer",
			origin: "://bad",
			referer: "https://good.example.com",
			want:   "good.example.com",
		},
		{
			name:   "origin with trailing slash",
			origin: "https://api.example.com/",
			referer: "",
			want:   "api.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractRequestDomain(tt.origin, tt.referer)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsDomainAllowed(t *testing.T) {
	tests := []struct {
		name        string
		requestHost string
		whitelist   []string
		want        bool
	}{
		{
			name:        "empty whitelist allows any",
			requestHost: "any.example.com",
			whitelist:   nil,
			want:        true,
		},
		{
			name:        "empty whitelist slice allows any",
			requestHost: "evil.com",
			whitelist:   []string{},
			want:        true,
		},
		{
			name:        "exact match",
			requestHost: "example.com",
			whitelist:   []string{"example.com"},
			want:        true,
		},
		{
			name:        "exact match multiple entries",
			requestHost: "allowed.com",
			whitelist:   []string{"other.com", "allowed.com"},
			want:        true,
		},
		{
			name:        "subdomain match",
			requestHost: "app.example.com",
			whitelist:   []string{"example.com"},
			want:        true,
		},
		{
			name:        "subdomain match deep",
			requestHost: "api.app.example.com",
			whitelist:   []string{"example.com"},
			want:        true,
		},
		{
			name:        "no match",
			requestHost: "evil.com",
			whitelist:   []string{"example.com"},
			want:        false,
		},
		{
			name:        "suffix not subdomain",
			requestHost: "notexample.com",
			whitelist:   []string{"example.com"},
			want:        false,
		},
		{
			name:        "case normalized",
			requestHost: "Example.COM",
			whitelist:   []string{"example.com"},
			want:        true,
		},
		{
			name:        "whitelist entry case normalized",
			requestHost: "example.com",
			whitelist:   []string{"Example.COM"},
			want:        true,
		},
		{
			name:        "empty request host with non-empty whitelist",
			requestHost: "",
			whitelist:   []string{"example.com"},
			want:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsDomainAllowed(tt.requestHost, tt.whitelist)
			assert.Equal(t, tt.want, got)
		})
	}
}
