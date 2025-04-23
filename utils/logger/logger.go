package logger

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	sentryhook "github.com/chadsr/logrus-sentry"
	"github.com/getsentry/sentry-go"
	"github.com/paycrest/aggregator/config"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

func init() {
	logger.Level = logrus.InfoLevel
	logger.Formatter = &formatter{}

	config := config.ServerConfig()
	if config.Environment == "production" || config.Environment == "staging" {
		// init sentry
		err := sentry.Init(sentry.ClientOptions{
			Dsn: config.SentryDSN,
			AttachStacktrace: true,
		})
		if err != nil {
			logger.Fatalf("Sentry initialization failed: %v", err)
		}

		// Sentry hook
		hook := sentryhook.New([]logrus.Level{
			logrus.PanicLevel,
			logrus.FatalLevel,
			logrus.ErrorLevel,
		})
		logger.Hooks.Add(hook)
	} else {
		// File hook for local environment

		// Get the directory of the executable
		ex, err := os.Executable()
		if err != nil {
			logger.Errorf("Failed to get the executable path: %v", err)
			return
		}

		// Get the directory of the executable
		exDir := filepath.Dir(ex)

		// Construct the file path in the same directory as the executable
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

// SetLogLevel sets the log level for the logger.
func SetLogLevel(level logrus.Level) {
	logger.Level = level
}

// Fields type, used to pass to `WithFields`.
type Fields logrus.Fields

// WithFields returns a new entry with the provided fields and automatically adds caller information.
func WithFields(fields Fields) *logrus.Entry {
	// Get caller information (skip 1 stack frame to get the caller of WithFields)
	_, file, line, ok := runtime.Caller(1)
	if ok {
		// Extract just the filename without the full path
		_, fileName := filepath.Split(file)

		// Add caller information to fields
		logrusFields := logrus.Fields(fields)
		if _, exists := logrusFields["file"]; !exists {
			logrusFields["File"] = fileName
		}
		if _, exists := logrusFields["line"]; !exists {
			logrusFields["Line"] = line
		}

		// Try to get function name
		pc, _, _, funcOk := runtime.Caller(1)
		if funcOk {
			funcName := runtime.FuncForPC(pc).Name()
			// Extract just the function name without the full package path
			if lastDot := strings.LastIndex(funcName, "."); lastDot != -1 {
				funcName = funcName[lastDot+1:]
			}
			if _, exists := logrusFields["function"]; !exists {
				logrusFields["Function"] = funcName
			}
		}

		return logger.WithFields(logrusFields)
	}

	return logger.WithFields(logrus.Fields(fields))
}

// WithField returns a new entry with the provided field and automatically adds caller information.
func WithField(key string, value interface{}) *logrus.Entry {
	return WithFields(Fields{key: value})
}

// Debugf logs a message at level Debug on the standard logger.
func Debugf(format string, args ...interface{}) {
	if logger.Level >= logrus.DebugLevel {
		entry := logger.WithFields(logrus.Fields{})
		entry.Debugf(format, args...)
	}
}

// Infof logs a message at level Info on the standard logger.
func Infof(format string, args ...interface{}) {
	if logger.Level >= logrus.InfoLevel {
		entry := logger.WithFields(logrus.Fields{})
		entry.Infof(format, args...)
	}
}

// Warnf logs a message at level Warn on the standard logger.
func Warnf(format string, args ...interface{}) {
	if logger.Level >= logrus.WarnLevel {
		entry := logger.WithFields(logrus.Fields{})
		entry.Warnf(format, args...)
	}
}

// Errorf logs a message at level Error on the standard logger.
func Errorf(format string, args ...interface{}) {
	if logger.Level >= logrus.ErrorLevel {
		entry := logger.WithFields(logrus.Fields{})
		entry.Errorf(format, args...)
	}
}

// Fatalf logs a message at level Fatal on the standard logger.
func Fatalf(format string, args ...interface{}) {
	if logger.Level >= logrus.FatalLevel {
		entry := logger.WithFields(logrus.Fields{})
		entry.Fatalf(format, args...)
	}
}

// Formatter implements logrus.Formatter interface.
type formatter struct {
	prefix string
}

// Format building log message.
func (f *formatter) Format(entry *logrus.Entry) ([]byte, error) {
	var sb bytes.Buffer

	sb.WriteString(strings.ToUpper(entry.Level.String()))
	sb.WriteString(" ")
	sb.WriteString(entry.Time.Format(time.RFC3339))
	sb.WriteString(" ")
	sb.WriteString(f.prefix)
	sb.WriteString(entry.Message)

	// Add fields to the log message if there are any
	if len(entry.Data) > 0 {
		sb.WriteString(" | ")
		first := true
		for k, v := range entry.Data {
			if first {
				first = false
			} else {
				sb.WriteString(", ")
			}
			sb.WriteString(k)
			sb.WriteString("=")
			sb.WriteString(fmt.Sprintf("%v", v))
		}
	}

	sb.WriteString("\n")
	return sb.Bytes(), nil
}
