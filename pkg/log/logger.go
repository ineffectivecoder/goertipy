package log

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// Level represents the logging level
type Level int

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

// Logger provides structured logging for goertipy
type Logger struct {
	mu     sync.Mutex
	level  Level
	writer io.Writer
}

var defaultLogger = &Logger{
	level:  LevelError,
	writer: os.Stderr,
}

// Default returns the default logger
func Default() *Logger {
	return defaultLogger
}

// New creates a new logger with the given level
func New(level Level, writer io.Writer) *Logger {
	return &Logger{
		level:  level,
		writer: writer,
	}
}

// SetLevel changes the log level
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(LevelDebug, "[DBG]", format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(LevelInfo, "[*]", format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(LevelWarn, "[!]", format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(LevelError, "[ERR]", format, args...)
}

func (l *Logger) log(level Level, prefix, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if level > l.level {
		return
	}

	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.writer, "%s %s\n", prefix, msg)
}
