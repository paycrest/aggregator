package services

import (
	"runtime"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/paycrest/aggregator/utils/logger"
)

type GlitchTipService struct {
	glitchTipDSN string
}

type AlertLevel string

const (
	LevelInfo    AlertLevel = "info"
	LevelWarning AlertLevel = "warning"
	LevelError   AlertLevel = "error"
	LevelFatal   AlertLevel = "fatal"
)

// GlitchTipAlert represents the structure for GlitchTip alerts
type GlitchTipAlert struct {
	ProjectName string                 `json:"project_name"`
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	Level       AlertLevel             `json:"level"`
	URL         string                 `json:"url,omitempty"`
	Function    string                 `json:"function,omitempty"`
	Environment string                 `json:"environment,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
}

func NewGlitchTipService(glitchTipDSN string) *GlitchTipService {
	service := &GlitchTipService{
		glitchTipDSN: glitchTipDSN,
	}

	if glitchTipDSN != "" {
		err := sentry.Init(sentry.ClientOptions{
			Dsn:              glitchTipDSN,
			Environment:      "production",
			TracesSampleRate: 1.0,
		})
		if err != nil {
			logger.Errorf("Failed to initialize GlitchTip: %v", err)
		}
	}

	return service
}

func (s *GlitchTipService) SendGlitchTipAlert(alert *GlitchTipAlert) error {
	// Only send to GlitchTip
	return s.sendToGlitchTip(alert)
}

func (s *GlitchTipService) sendToGlitchTip(alert *GlitchTipAlert) error {
	if s.glitchTipDSN == "" {
		return nil
	}

	// Capture runtime information
	pc, file, line, ok := runtime.Caller(1)
	functionName := ""
	if ok {
		function := runtime.FuncForPC(pc)
		if function != nil {
			fullFunctionName := function.Name()
			functionName = fullFunctionName[strings.LastIndex(fullFunctionName, ".")+1:]
		}
		file = file[strings.LastIndex(file, "/")+1:]
	}

	// Add additional context and structured data
	sentry.WithScope(func(scope *sentry.Scope) {
		// Create an event with proper structure
		event := sentry.Event{
			Message:     alert.Message,
			ServerName:  alert.ProjectName,
			Environment: alert.Environment,
			Level:       sentry.Level(alert.Level),
			Extra: map[string]interface{}{
				"file":     file,
				"function": functionName,
				"line":     line,
			},
			Tags: map[string]string{
				"project": alert.ProjectName,
				"title":   alert.Title,
			},
		}

		// Capture the event
		eventID := sentry.CaptureEvent(&event)
		if eventID == nil {
			logger.Errorf("Failed to send event to GlitchTip")
		}
	})

	// Ensure events are sent before continuing
	if ok := sentry.Flush(5 * time.Second); !ok {
		logger.Warnf("Failed to flush all events to GlitchTip")
	}

	return nil
}
