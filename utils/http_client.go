package utils

import (
	"net"
	"net/http"
	"time"
)

var (
	// httpClient is a singleton HTTP client with proper connection pooling
	// This prevents creating new clients repeatedly and exhausting file descriptors
	httpClient *http.Client
)

func init() {
	// Create a single, reusable HTTP client with connection pooling
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	httpClient = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// GetHTTPClient returns the singleton HTTP client for reuse
// This ensures proper connection pooling and prevents resource leaks
func GetHTTPClient() *http.Client {
	return httpClient
}

// CloseHTTPClient closes the HTTP client's idle connections
// Call this during graceful shutdown
func CloseHTTPClient() {
	if httpClient != nil && httpClient.Transport != nil {
		httpClient.CloseIdleConnections()
	}
}
