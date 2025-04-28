package services

import (
	"testing"
	"time"

	"github.com/paycrest/aggregator/config"
	"github.com/stretchr/testify/assert"
)

var cnfg = config.ServerConfig()

func TestGlitchTipService(t *testing.T) {
	// Create a test alert
	mockAlert := &GlitchTipAlert{
		ProjectName: "Aggregator",
		Title:       "Test Alert",
		Message:     "Testing GlitchTip alert...",
		Level:       LevelError,
		URL:         "https://example.com/test",
		Function:    "TestFunction",
		Environment: "test",
		Timestamp:   time.Now(),
	}

	// Initialize the GlitchTipService with configurations
	service := NewGlitchTipService(cnfg.GlitchTipDSN)

	// Send the alert to GlitchTip
	err := service.SendGlitchTipAlert(mockAlert)
	assert.NoError(t, err)
}
