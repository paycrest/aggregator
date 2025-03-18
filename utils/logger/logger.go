package logger

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/paycrest/aggregator/config"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

func init() {

	logger.Level = logrus.InfoLevel
	logger.Formatter = &formatter{}
	cfg := config.ServerConfig()

	if cfg.Environment == "production" || cfg.Environment == "staging" {
		err := sentry.Init(sentry.ClientOptions{
			Dsn:              cfg.SentryDSN,
			Environment:      cfg.Environment,
			AttachStacktrace: true,
			BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
				return event
			},
		})
		if err != nil {
			logger.Fatalf("Sentry initialization failed: %v", err)
		}
	} else {
		ex, err := os.Executable()
		if err != nil {
			logger.Errorf("Failed to get the executable path: %v", err)
			return
		}
		exDir := filepath.Dir(ex)
		filePath := filepath.Join(exDir, "logs.txt")
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			logger.Out = file
		} else {
			logger.Errorf("Failed to open logs.txt: %v", err)
		}
	}
	logger.SetReportCaller(true)
}

// InitForTest initializes the logger with custom config and executable path for testing
func InitForTest(cfg config.ServerConfiguration, output io.Writer, executablePath string) {
	logger.Level = logrus.InfoLevel
	logger.Formatter = &formatter{}
	logger.Out = output

	if cfg.Environment == "production" || cfg.Environment == "staging" {
		err := sentry.Init(sentry.ClientOptions{
			Dsn:              cfg.SentryDSN,
			Environment:      cfg.Environment,
			AttachStacktrace: true,
			BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
				return event
			},
		})
		if err != nil {
			logger.Fatalf("Sentry initialization failed: %v", err)
		}
	} else {
		if executablePath != "" {
			exDir := filepath.Dir(executablePath)
			filePath := filepath.Join(exDir, "logs.txt")
			file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err == nil {
				logger.Out = file
			} else {
				logger.Errorf("Failed to open logs.txt: %v", err)
			}
		}
	}
	logger.SetReportCaller(true)
}

// SetLogLevel sets the log level for the logger.
func SetLogLevel(level logrus.Level) {
	logger.Level = level
}

// Fields type, used to pass to `WithFields`.
type Fields logrus.Fields

// ErrorWithFields logs an error with additional context
func ErrorWithFields(err error, fields Fields) {
	if logger.Level >= logrus.ErrorLevel {
		wrappedErr := fmt.Errorf("error occurred: %w", err) // Add context
		sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetLevel(sentry.LevelError) // Explicitly set level
			for key, value := range fields {
				switch v := value.(type) {
				case string:
					scope.SetTag(key, v)
				default:
					scope.SetExtra(key, value)
				}
			}
			sentry.CaptureException(wrappedErr)
		})
		logger.WithFields(logrus.Fields(fields)).Error(wrappedErr.Error())
	}
}

// Debugf logs a message at level Debug with optional fields
func Debugf(format string, fields Fields, args ...interface{}) {
	if logger.Level >= logrus.DebugLevel {
		entry := logger.WithFields(logrus.Fields(fields))
		entry.Debugf(format, args...)
	}
}

// Infof logs a message at level Info with optional fields
func Infof(format string, fields Fields, args ...interface{}) {
	if logger.Level >= logrus.InfoLevel {
		entry := logger.WithFields(logrus.Fields(fields))
		entry.Infof(format, args...)
	}
}

// Warnf logs a message at level Warn with optional fields
func Warnf(format string, fields Fields, args ...interface{}) {
	if logger.Level >= logrus.WarnLevel {
		sentry.WithScope(func(scope *sentry.Scope) {
			for key, value := range fields {
				scope.SetExtra(key, value)
			}
			sentry.CaptureMessage(fmt.Sprintf(format, args...))
		})
		entry := logger.WithFields(logrus.Fields(fields))
		entry.Warnf(format, args...)
	}
}

// Errorf logs an error message with fields and stack trace
func Errorf(format string, fields Fields, args ...interface{}) {
	if logger.Level >= logrus.ErrorLevel {
		errMsg := fmt.Sprintf(format, args...)
		sentry.WithScope(func(scope *sentry.Scope) {
			for key, value := range fields {
				switch v := value.(type) {
				case string:
					scope.SetTag(key, v)
				default:
					scope.SetExtra(key, value)
				}
			}
			sentry.CaptureMessage(errMsg)
		})
		logger.WithFields(logrus.Fields(fields)).Error(errMsg)
	}
}

// Fatalf logs a fatal message with fields
func Fatalf(format string, fields Fields, args ...interface{}) {
	if logger.Level >= logrus.FatalLevel {
		errMsg := fmt.Sprintf(format, args...)
		sentry.WithScope(func(scope *sentry.Scope) {
			for key, value := range fields {
				scope.SetExtra(key, value)
			}
			sentry.CaptureMessage(errMsg)
		})
		entry := logger.WithFields(logrus.Fields(fields))
		entry.Fatalf(format, args...)
	}
}

// Formatter implements logrus.Formatter interface
type formatter struct {
	prefix string
}

// Format building log message
func (f *formatter) Format(entry *logrus.Entry) ([]byte, error) {
	var sb bytes.Buffer
	sb.WriteString(strings.ToUpper(entry.Level.String()))
	sb.WriteString(" ")
	sb.WriteString(entry.Time.Format(time.RFC3339))
	sb.WriteString(" ")
	sb.WriteString(f.prefix)
	sb.WriteString(entry.Message)

	if len(entry.Data) > 0 {
		sb.WriteString(" [")
		for key, value := range entry.Data {
			sb.WriteString(fmt.Sprintf("%s=%v ", key, value))
		}
		sb.WriteString("]")
	}
	sb.WriteString("\n")

	return sb.Bytes(), nil
}
