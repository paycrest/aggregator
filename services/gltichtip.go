package services

import (
	"os"
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
			// Disable email notifications
			BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
				// Disable email notifications by removing email addresses
				event.User.Email = ""
				return event
			},
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

	var eventID *sentry.EventID

	// Add additional context and structured data
	sentry.WithScope(func(scope *sentry.Scope) {
		// Set scope properties
		scope.SetTag("project", alert.ProjectName)
		scope.SetLevel(sentry.Level(alert.Level))

		event := sentry.Event{
			Message:     alert.Message,
			ServerName:  alert.ProjectName,
			Environment: alert.Environment,
			Level:       sentry.Level(alert.Level),
			Extra: map[string]interface{}{
				"file":     file,
				"line":     line,
				"function": functionName,
			},
		}

		// Add release info if available
		if release := os.Getenv("RELEASE_VERSION"); release != "" {
			event.Release = release
		}

		if alert.Extra != nil {
			for k, v := range alert.Extra {
				event.Extra[k] = v
			}
		}

		// Capture the event and store the ID
		eventID = sentry.CaptureEvent(&event)
		if eventID == nil {
			logger.Errorf("Failed to send event to GlitchTip")
		}
	})

	// Ensure events are sent before continuing
	if ok := sentry.Flush(2 * time.Second); !ok {
		logger.Warnf("Failed to flush all events to GlitchTip")
	}

	return nil
}
