package services

import (
	"testing"
	"time"

	"github.com/paycrest/aggregator/config"
	"github.com/stretchr/testify/assert"
)

var cnfg = config.ServerConfig()

func TestRealGlitchTipService(t *testing.T) {
	// Create a real alert
	mockAlert := &GlitchTipAlert{
		ProjectName: "Real Project",
		Title:       "Real Alert",
		Message:     "This is a real alert for testing purposes...",
		Level:       LevelError,
		URL:         "https://example.com/error",
		Function:    "real_function",
		Environment: "production",
		Timestamp:   time.Now(),
	}

	// Initialize the GlitchTipService with real configurations
	service := NewGlitchTipService(cnfg.SlackWebhookURL, cnfg.GlitchTipDSN)

	// Send the alert to both Slack and GlitchTip
	err := service.SendGlitchTipAlert(mockAlert)
	assert.NoError(t, err)
}
