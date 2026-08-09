package logger

import (
	"log/slog"
	"os"
)

// структура для хранения логгера
type Logger struct {
	log *slog.Logger
}

func NewLogger() *Logger {
	// создаём логер
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	return &Logger{
		log: slog.New(handler),
	}
}

func (l *Logger) Info(msg string, args ...any) {
	l.log.Info(msg, args...)
}

func (l *Logger) Error(msg string, args ...any) {
	l.log.Error(msg, args...)
}
