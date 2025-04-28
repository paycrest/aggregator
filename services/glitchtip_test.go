package services

import (
	"os"
	"testing"
	"time"

	"github.com/paycrest/aggregator/config"
	"github.com/stretchr/testify/assert"
)

var cnfg = config.ServerConfig()

func TestGlitchTipService(t *testing.T) {
	// Set test release version
	os.Setenv("RELEASE_VERSION", "v1.0.0")
	defer os.Unsetenv("RELEASE_VERSION")

	tests := []struct {
		name    string
		alert   *GlitchTipAlert
		wantErr bool
	}{
		{
			name: "error alert",
			alert: &GlitchTipAlert{
				ProjectName: "Payment Service",
				Title:       "Transaction Processing Failed",
				Message:     "Failed to process transaction: timeout",
				Level:       LevelError,
				Environment: "test",
				Timestamp:   time.Now(),
			},
			wantErr: false,
		},
		{
			name: "info alert",
			alert: &GlitchTipAlert{
				ProjectName: "System Monitor",
				Title:       "Daily Health Check",
				Message:     "All systems operational",
				Level:       LevelInfo,
				Environment: "test",
				Timestamp:   time.Now(),
			},
			wantErr: false,
		},
	}

	service := NewGlitchTipService(cnfg.GlitchTipDSN)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.SendGlitchTipAlert(tt.alert)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
