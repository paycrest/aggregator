package services

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
)

type GlitchTipService struct {
	slackWebhookURL string
	glitchTipDSN    string
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

func NewGlitchTipService(slackWebhookURL, glitchTipDSN string) *GlitchTipService {
	service := &GlitchTipService{
		slackWebhookURL: slackWebhookURL,
		glitchTipDSN:    glitchTipDSN,
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
	errChan := make(chan error, 2)

	// Send to Slack
	go func() {
		errChan <- s.sendToSlack(alert)
	}()

	// Send to GlitchTip
	go func() {
		errChan <- s.sendToGlitchTip(alert)
	}()

	var errors []error
	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("notification errors: %v", errors)
	}

	return nil
}

func (s *GlitchTipService) sendToSlack(alert *GlitchTipAlert) error {
	if s.slackWebhookURL == "" {
		return nil
	}

	// Format the timestamp
	formattedTime, err := utils.FormatTimestampToGMT1(alert.Timestamp)
	if err != nil {
		return fmt.Errorf("error formatting timestamp: %w", err)
	}

	message := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"title":      alert.Title,
				"title_link": alert.URL,
				"text":       alert.Message,
				"fields": []map[string]interface{}{
					{
						"title": "Project",
						"value": alert.ProjectName,
						"short": false,
					},
					{
						"title": "Level",
						"value": alert.Level,
						"short": false,
					},
					{
						"title": "Function",
						"value": alert.Function,
						"short": false,
					},
					{
						"title": "Environment",
						"value": alert.Environment,
						"short": false,
					},
				},

				"footer": formattedTime,
			},
		},
	}

	// Send the message to Slack
	jsonPayload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("error marshaling Slack message: %w", err)
	}

	resp, err := http.Post(s.slackWebhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("error sending Slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack notification failed with status: %d", resp.StatusCode)
	}

	return nil
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
			// Extract only the function name (last part of the full path)
			fullFunctionName := function.Name()
			functionName = fullFunctionName[strings.LastIndex(fullFunctionName, ".")+1:]
		}

		// Extract only the file name (last part of the full path)
		file = file[strings.LastIndex(file, "/")+1:]
	}

	// Add additional context and structured data
	sentry.WithScope(func(scope *sentry.Scope) {
		// Add tags
		scope.SetTag("ProjectName", alert.ProjectName)
		scope.SetTag("Environment", alert.Environment)

		// Add extra data
		scope.SetExtras(map[string]interface{}{
			"Error":    alert.Message,
			"File":     file,
			"Function": functionName,
			"Line":     line,
		})

		// Capture the exception
		eventID := sentry.CaptureException(errors.New(alert.Message))
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
