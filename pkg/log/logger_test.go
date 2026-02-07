package log

import (
	"bytes"
	"strings"
	"testing"
)

func TestLoggerLevels(t *testing.T) {
	var buf bytes.Buffer
	l := New(LevelDebug, &buf)

	l.Debug("debug %d", 1)
	l.Info("info %s", "msg")
	l.Warn("warn")
	l.Error("error")

	output := buf.String()
	if !strings.Contains(output, "[DBG] debug 1") {
		t.Errorf("expected debug message, got %q", output)
	}
	if !strings.Contains(output, "[*] info msg") {
		t.Errorf("expected info message, got %q", output)
	}
	if !strings.Contains(output, "[!] warn") {
		t.Errorf("expected warn message, got %q", output)
	}
	if !strings.Contains(output, "[ERR] error") {
		t.Errorf("expected error message, got %q", output)
	}
}

func TestLoggerFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := New(LevelWarn, &buf)

	l.Debug("should not appear")
	l.Info("should not appear")
	l.Warn("should appear")
	l.Error("should appear")

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 log lines, got %d: %q", len(lines), output)
	}
}

func TestLoggerSetLevel(t *testing.T) {
	var buf bytes.Buffer
	l := New(LevelError, &buf)

	l.Info("hidden")
	if buf.Len() != 0 {
		t.Error("info should be hidden at error level")
	}

	l.SetLevel(LevelInfo)
	l.Info("visible")
	if !strings.Contains(buf.String(), "visible") {
		t.Error("info should be visible after SetLevel")
	}
}

func TestDefaultLogger(t *testing.T) {
	l := Default()
	if l == nil {
		t.Fatal("Default() returned nil")
	}
}
