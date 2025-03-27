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

// Logger instance
var logger = logrus.New()

// InitLogger initializes the logger with the given configuration, output, and executable path.
func InitLogger(cfg *config.ServerConfiguration, output io.Writer, executablePath string) {
	if cfg == nil {
		cfg = config.ServerConfig()
	}

	logger.Level = logrus.InfoLevel
	logger.Formatter = &formatter{}

	// Environment-specific configuration
	if cfg.Environment == "production" || cfg.Environment == "staging" {
		if err := sentry.Init(sentry.ClientOptions{
			Dsn:              cfg.SentryDSN,
			Environment:      cfg.Environment,
			AttachStacktrace: true,
			BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
				return event
			},
		}); err != nil {
			logger.Fatalf("Sentry initialization failed: %v", err)
		}
		sentry.ConfigureScope(func(scope *sentry.Scope) {
			scope.SetTag("environment", cfg.Environment)
			scope.SetExtra("app_version", "1.0.0")
		})
		// Use provided output or default to stdout
		if output == nil {
			logger.Out = os.Stdout
		} else {
			logger.Out = output
		}
	} else if executablePath != "" {
		// In development, prioritize file output
		exDir := filepath.Dir(executablePath)
		if err := os.MkdirAll(exDir, 0755); err != nil {
			logger.Errorf("Failed to create directory %s: %v", exDir, err)
		}
		filePath := filepath.Join(exDir, "logs.txt")
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			logger.Errorf("Failed to open logs.txt: %v", err)
			// Fallback to provided output or stdout
			if output == nil {
				logger.Out = os.Stdout
			} else {
				logger.Out = output
			}
		} else {
			logger.Out = file // Default to file output in development
		}
	} else {
		// Fallback for no executablePath
		if output == nil {
			logger.Out = os.Stdout
		} else {
			logger.Out = output
		}
	}

	logger.SetReportCaller(true)
}

func init() {
	cfg := config.ServerConfig()
	ex, err := os.Executable()
	if err != nil {
		logger.Errorf("Failed to get the executable path: %v", err)
		ex = ""
	}
	InitLogger(cfg, nil, ex)
}

// InitForTest is a wrapper for testing
func InitForTest(cfg *config.ServerConfiguration, output io.Writer, executablePath string) {
	InitLogger(cfg, output, executablePath)
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
		wrappedErr := fmt.Errorf("error occurred: %w", err)
		sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetLevel(sentry.LevelError)
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
		logger.WithFields(logrus.Fields(fields)).Error(wrappedErr)
	}
}

// Debugf logs a message at level Debug with optional fields
func Debugf(format string, fields Fields, args ...interface{}) {
	if logger.Level >= logrus.DebugLevel {
		logger.WithFields(logrus.Fields(fields)).Debugf(format, args...)
	}
}

// Infof logs a message at level Info with optional fields
func Infof(format string, fields Fields, args ...interface{}) {
	if logger.Level >= logrus.InfoLevel {
		logger.WithFields(logrus.Fields(fields)).Infof(format, args...)
	}
}

// Warnf logs a message at level Warn with optional fields
func Warnf(format string, fields Fields, args ...interface{}) {
	if logger.Level >= logrus.WarnLevel {
		wrappedErr := fmt.Errorf(format, args...) // Create error for stack trace
		sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetLevel(sentry.LevelWarning)
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
		logger.WithFields(logrus.Fields(fields)).Warnf(format, args...)
	}
}

// Errorf logs an error message with fields and stack trace
func Errorf(format string, fields Fields, args ...interface{}) {
	if logger.Level >= logrus.ErrorLevel {
		// Create the error directly with fmt.Errorf, avoiding intermediate fmt.Sprintf
		wrappedErr := fmt.Errorf(format, args...)
		sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetLevel(sentry.LevelError)
			for key, value := range fields {
				switch v := value.(type) {
				case string:
					scope.SetTag(key, v)
				default:
					scope.SetExtra(key, value)
				}
			}
			sentry.CaptureException(wrappedErr) // Capture the error with stack trace
		})
		// Log the formatted message directly
		logger.WithFields(logrus.Fields(fields)).Errorf(format, args...)
	}
}

// Fatalf logs a fatal message with fields
func Fatalf(format string, fields Fields, args ...interface{}) {
	if logger.Level >= logrus.FatalLevel {
		wrappedErr := fmt.Errorf(format, args...)
		sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetLevel(sentry.LevelFatal)
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
		logger.WithFields(logrus.Fields(fields)).Fatal(wrappedErr)
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
