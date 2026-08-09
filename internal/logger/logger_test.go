package logger

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLogger(t *testing.T) {
	l := NewLogger()

	require.NotNil(t, l)
	assert.NotNil(t, l.log)
}

func TestLogger_Info(t *testing.T) {
	l := NewLogger()

	assert.NotPanics(t, func() {
		l.Info("test info message")
	})
}

func TestLogger_Error(t *testing.T) {
	l := NewLogger()

	assert.NotPanics(t, func() {
		l.Error("test error message")
	})
}

func TestLogger_WithArgs(t *testing.T) {
	l := NewLogger()

	assert.NotPanics(t, func() {
		l.Info(
			"user login",
			"user", "marina",
			"id", 123,
		)

		l.Error(
			"request failed",
			"status", 500,
			"path", "/api/test",
		)
	})
}
