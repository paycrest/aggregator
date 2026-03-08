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
// Preserves default transport behaviors such as proxy handling and TLS settings.
//
// When http.DefaultTransport is not a *http.Transport (e.g. httpmock is active), the client
// is not cached: each call returns a new client using the current DefaultTransport. That way
// tests can activate/deactivate httpmock and the next GetHTTPClient() always uses the current
// transport, avoiding a stale or defunct transport after httpmock.Deactivate().
func GetHTTPClient() *http.Client {
	if _, ok := http.DefaultTransport.(*http.Transport); !ok {
		return &http.Client{
			Transport: http.DefaultTransport,
			Timeout:   30 * time.Second,
		}
	}
	once.Do(func() {
		defaultTransport := http.DefaultTransport.(*http.Transport)
		// Clone the default transport to preserve default behaviors
		// (proxy, TLS, dial context, etc.) when available in production.
		// Copy critical fields to maintain forward compatibility
		// and reduce coupling to http.Transport implementation details.
		// ForceAttemptHTTP2 and ExpectContinueTimeout must be copied so HTTP/2
		// and 100-Continue behavior match the default transport.
		rt := &http.Transport{
			Proxy:                 defaultTransport.Proxy,
			DialContext:           defaultTransport.DialContext,
			TLSClientConfig:       defaultTransport.TLSClientConfig,
			TLSHandshakeTimeout:   defaultTransport.TLSHandshakeTimeout,
			DisableKeepAlives:     defaultTransport.DisableKeepAlives,
			DisableCompression:    defaultTransport.DisableCompression,
			ForceAttemptHTTP2:     defaultTransport.ForceAttemptHTTP2,
			ExpectContinueTimeout: defaultTransport.ExpectContinueTimeout,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
		}
		httpClient = &http.Client{
			Transport: rt,
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
