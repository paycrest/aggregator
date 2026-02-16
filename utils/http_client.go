package utils

import (
	"net/http"
	"sync"
	"time"
)

var (
	httpClient *http.Client
	once       sync.Once
)

// GetHTTPClient returns a singleton HTTP client with proper connection pooling.
// This prevents creating new clients repeatedly and ensures connections are reused.
// The client has:
// - MaxIdleConns: 100 (max idle connections in connection pool)
// - MaxIdleConnsPerHost: 10 (max idle connections per host)
// - IdleConnTimeout: 90 seconds (connections are closed after 90 seconds of inactivity)
func GetHTTPClient() *http.Client {
	once.Do(func() {
		transport := &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		}
		httpClient = &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}
	})
	return httpClient
}

// CloseHTTPClient closes idle connections in the HTTP client.
// Call this during graceful shutdown to clean up resources.
func CloseHTTPClient() {
	if httpClient != nil && httpClient.Transport != nil {
		if transport, ok := httpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
}
