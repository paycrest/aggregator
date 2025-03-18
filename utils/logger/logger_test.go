package logger

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/paycrest/aggregator/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// MockConfig mocks the ServerConfig for testing
type MockConfig struct {
	Environment string
	SentryDSN   string
}

func (m MockConfig) ServerConfig() *config.ServerConfiguration {
	return &config.ServerConfiguration{
		Environment: m.Environment,
		SentryDSN:   m.SentryDSN,
	}
}

func TestLoggerComprehensive(t *testing.T) {
	conf := config.ServerConfig()
	if conf.SentryDSN == "" {
		t.Fatal("SENTRY_DSN not set in config.ServerConfig(), cannot send to Sentry")
	}

	tempDir := t.TempDir()
	var buf bytes.Buffer

	reinitLogger := func(env string, executablePath string) {
		buf.Reset()
		mockCfg := MockConfig{
			Environment: env,
			SentryDSN:   conf.SentryDSN,
		}
		InitForTest(mockCfg.ServerConfig(), &buf, executablePath)
	}

	tests := []struct {
		name           string
		env            string
		executablePath string
		action         func(t *testing.T)
		verify         func(t *testing.T, output string, fileContent string)
	}{
		{
			name:           "Production with ErrorWithFields",
			env:            "production",
			executablePath: "",
			action: func(t *testing.T) {
				reinitLogger("production", "")
				testErr := errors.New("test error from go test")
				fields := Fields{
					"order_id": "123",
					"user_id":  456,
					"test":     true,
				}
				t.Log("Sending wrapped error to Sentry")
				ErrorWithFields(testErr, fields)
				time.Sleep(100 * time.Millisecond)
			},
			verify: func(t *testing.T, output string, fileContent string) {
				assert.Contains(t, output, "ERROR", "Should contain error level")
				assert.Contains(t, output, "error occurred: test error from go test", "Should contain wrapped error message")
				assert.Contains(t, output, "order_id=123", "Should contain field order_id")
				assert.Contains(t, output, "user_id=456", "Should contain field user_id")
				assert.Empty(t, fileContent, "No file output in production")
				t.Log("Check Sentry for event: 'error occurred: test error from go test' with tags order_id=123, extra user_id=456, test=true, level=error")
			},
		},
		{
			name:           "Development with Infof",
			env:            "development",
			executablePath: filepath.Join(tempDir, "test"),
			action: func(t *testing.T) {
				reinitLogger("development", filepath.Join(tempDir, "test"))
				Infof("Test info %s", Fields{"key": "value"}, "message")
				time.Sleep(100 * time.Millisecond) // Allow file write
			},
			verify: func(t *testing.T, output string, fileContent string) {
				assert.Empty(t, output, "Output should go to file in development")
				assert.Contains(t, fileContent, "INFO", "Should contain info level")
				assert.Contains(t, fileContent, "Test info message", "Should contain formatted message")
				assert.Contains(t, fileContent, "key=value", "Should contain field")
			},
		},
		{
			name:           "Production with Errorf",
			env:            "production",
			executablePath: "",
			action: func(t *testing.T) {
				reinitLogger("production", "")
				Errorf("Payment failed %d", Fields{"amount": 99}, 1)
				time.Sleep(100 * time.Millisecond)
			},
			verify: func(t *testing.T, output string, fileContent string) {
				assert.Contains(t, output, "ERROR", "Should contain error level")
				assert.Contains(t, output, "Payment failed 1", "Should contain formatted message")
				assert.Contains(t, output, "amount=99", "Should contain field")
				assert.Empty(t, fileContent, "No file output in production")
				t.Log("Check Sentry for event: 'Payment failed 1' with extra amount=99, level=error")
			},
		},
		{
			name:           "Level Filtering in Development",
			env:            "development",
			executablePath: filepath.Join(tempDir, "test"),
			action: func(t *testing.T) {
				reinitLogger("development", filepath.Join(tempDir, "test"))
				SetLogLevel(logrus.WarnLevel)
				Debugf("Debug %s", Fields{}, "test")
				Infof("Info %s", Fields{}, "test")
				Warnf("Warn %s", Fields{}, "test")
				time.Sleep(100 * time.Millisecond) // Allow file write
			},
			verify: func(t *testing.T, output string, fileContent string) {
				assert.Empty(t, output, "Output should go to file in development")
				assert.NotContains(t, fileContent, "DEBUG", "Debug should be filtered")
				assert.NotContains(t, fileContent, "INFO", "Info should be filtered")
				assert.Contains(t, fileContent, "WARN", "Warn should appear")
				assert.Contains(t, fileContent, "Warn test", "Warn message should appear")
			},
		},
		{
			name:           "Staging with Warnf",
			env:            "staging",
			executablePath: "",
			action: func(t *testing.T) {
				reinitLogger("staging", "")
				Warnf("Warning %s", Fields{"reason": "test"}, "condition")
				time.Sleep(100 * time.Millisecond)
			},
			verify: func(t *testing.T, output string, fileContent string) {
				assert.Contains(t, output, "WARN", "Should contain warn level")
				assert.Contains(t, output, "Warning condition", "Should contain formatted message")
				assert.Contains(t, output, "reason=test", "Should contain field")
				assert.Empty(t, fileContent, "No file output in staging")
				t.Log("Check Sentry for event: 'Warning condition' with extra reason=test, level=warning")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.action(t)
			fileContent := ""
			if tt.env != "production" && tt.env != "staging" {
				filePath := filepath.Join(tempDir, "logs.txt")
				data, err := os.ReadFile(filePath)
				if err != nil {
					t.Errorf("Failed to read logs.txt: %v", err)
				} else {
					fileContent = string(data)
				}
				if err := os.Truncate(filePath, 0); err != nil {
					t.Errorf("Failed to truncate logs.txt: %v", err)
				}
			}
			tt.verify(t, buf.String(), fileContent)
		})
	}
}

func TestMain(m *testing.M) {
	result := m.Run()
	sentry.Flush(2 * time.Second)
	os.Exit(result)
}
