package utils

import (
	"testing"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/jarcoal/httpmock"
)

func TestFastshotBodyAsJSON(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	t.Run("successful JSON response", func(t *testing.T) {
		httpmock.RegisterResponder("GET", "https://test.example.com/success",
			httpmock.NewJsonResponderOrPanic(200, map[string]interface{}{
				"status": "success",
				"data":   "test",
			}))

		res, err := fastshot.DefaultClient("https://test.example.com").
			GET("/success").
			Send()

		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if res.Status().IsError() {
			t.Fatalf("Expected success, got error status: %d", res.Status().Code())
		}

		var data map[string]interface{}
		err = res.Body().AsJSON(&data)
		if err != nil {
			t.Fatalf("Failed to parse JSON: %v", err)
		}

		if data["status"] != "success" {
			t.Errorf("Expected status=success, got %v", data["status"])
		}
	})

	t.Run("4xx client error", func(t *testing.T) {
		httpmock.RegisterResponder("GET", "https://test.example.com/error400",
			httpmock.NewJsonResponderOrPanic(400, map[string]interface{}{
				"error": "bad request",
			}))

		res, err := fastshot.DefaultClient("https://test.example.com").
			GET("/error400").
			Send()

		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if !res.Status().IsError() {
			t.Error("Expected IsError() to be true for 400 status")
		}

		if !res.Status().Is4xxClientError() {
			t.Error("Expected Is4xxClientError() to be true")
		}

		if res.Status().Code() != 400 {
			t.Errorf("Expected status 400, got %d", res.Status().Code())
		}

		// Verify we can get body as string for error messages
		bodyStr, err := res.Body().AsString()
		if err != nil {
			t.Fatalf("Failed to read body: %v", err)
		}
		if bodyStr == "" {
			t.Error("Expected non-empty error body")
		}
	})

	t.Run("5xx server error", func(t *testing.T) {
		httpmock.RegisterResponder("GET", "https://test.example.com/error500",
			httpmock.NewJsonResponderOrPanic(500, map[string]interface{}{
				"error": "internal server error",
			}))

		res, err := fastshot.DefaultClient("https://test.example.com").
			GET("/error500").
			Send()

		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if !res.Status().IsError() {
			t.Error("Expected IsError() to be true for 500 status")
		}

		if !res.Status().Is5xxServerError() {
			t.Error("Expected Is5xxServerError() to be true")
		}

		if res.Status().Code() != 500 {
			t.Errorf("Expected status 500, got %d", res.Status().Code())
		}
	})

	t.Run("non-JSON response", func(t *testing.T) {
		httpmock.RegisterResponder("GET", "https://test.example.com/html",
			httpmock.NewStringResponder(200, "<html>Not JSON</html>"))

		res, err := fastshot.DefaultClient("https://test.example.com").
			GET("/html").
			Send()

		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		// First try to get body as string (before AsJSON consumes it)
		bodyStr, err := res.Body().AsString()
		if err != nil {
			t.Fatalf("Failed to read body: %v", err)
		}
		if bodyStr != "<html>Not JSON</html>" {
			t.Errorf("Expected HTML body, got %s", bodyStr)
		}

		// Now test with a fresh request that AsJSON will fail
		httpmock.RegisterResponder("GET", "https://test.example.com/html2",
			httpmock.NewStringResponder(200, "<html>Not JSON</html>"))

		res2, err := fastshot.DefaultClient("https://test.example.com").
			GET("/html2").
			Send()

		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		var data map[string]interface{}
		err = res2.Body().AsJSON(&data)
		if err == nil {
			t.Error("Expected JSON parsing to fail for non-JSON response")
		}
	})
}
