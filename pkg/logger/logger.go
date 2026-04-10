package logger

import (
	"fmt"
	"os"
	"strings"

	"winkyou/pkg/config"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	With(fields ...Field) Logger
	Sync() error
}

type Field struct {
	Key   string
	Value any
}

type zapLogger struct {
	base   *zap.Logger
	closer func() error
}

func New(cfg *config.LogConfig) (Logger, error) {
	return NewWithOptions(FromConfig(cfg))
}

func NewWithOptions(opts Options) (Logger, error) {
	if strings.TrimSpace(opts.Level) == "" {
		opts.Level = "info"
	}
	if strings.TrimSpace(opts.Format) == "" {
		opts.Format = "text"
	}
	if strings.TrimSpace(opts.Output) == "" {
		opts.Output = "stderr"
	}

	level, err := parseLevel(opts.Level)
	if err != nil {
		return nil, err
	}

	encoder := newEncoder(opts.Format)
	sink, closeFn, err := newSink(opts)
	if err != nil {
		return nil, err
	}

	core := zapcore.NewCore(encoder, sink, level)
	z := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	return &zapLogger{base: z, closer: closeFn}, nil
}

func (l *zapLogger) Debug(msg string, fields ...Field) {
	l.base.Debug(msg, toZapFields(fields)...)
}

func (l *zapLogger) Info(msg string, fields ...Field) {
	l.base.Info(msg, toZapFields(fields)...)
}

func (l *zapLogger) Warn(msg string, fields ...Field) {
	l.base.Warn(msg, toZapFields(fields)...)
}

func (l *zapLogger) Error(msg string, fields ...Field) {
	l.base.Error(msg, toZapFields(fields)...)
}

func (l *zapLogger) With(fields ...Field) Logger {
	return &zapLogger{base: l.base.With(toZapFields(fields)...)}
}

func (l *zapLogger) Sync() error {
	var syncErr error
	if l.base != nil {
		syncErr = l.base.Sync()
	}
	if l.closer != nil {
		if err := l.closer(); err != nil && syncErr == nil {
			syncErr = err
		}
	}
	return syncErr
}

func String(key, val string) Field {
	return Field{Key: key, Value: val}
}

func Int(key string, val int) Field {
	return Field{Key: key, Value: val}
}

func Bool(key string, val bool) Field {
	return Field{Key: key, Value: val}
}

func Any(key string, val any) Field {
	return Field{Key: key, Value: val}
}

func Error(err error) Field {
	return Field{Key: "error", Value: err}
}

func toZapFields(fields []Field) []zap.Field {
	out := make([]zap.Field, 0, len(fields))
	for _, field := range fields {
		out = append(out, zap.Any(field.Key, field.Value))
	}
	return out
}

func parseLevel(level string) (zapcore.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return zapcore.DebugLevel, nil
	case "info":
		return zapcore.InfoLevel, nil
	case "warn":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	default:
		return zapcore.InfoLevel, fmt.Errorf("invalid log level: %q", level)
	}
}

func newEncoder(format string) zapcore.Encoder {
	encCfg := zap.NewProductionEncoderConfig()
	encCfg.TimeKey = "time"
	encCfg.LevelKey = "level"
	encCfg.MessageKey = "msg"
	encCfg.CallerKey = "caller"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encCfg.EncodeLevel = zapcore.CapitalLevelEncoder
	encCfg.EncodeCaller = zapcore.ShortCallerEncoder

	if strings.EqualFold(strings.TrimSpace(format), "json") {
		return zapcore.NewJSONEncoder(encCfg)
	}

	return zapcore.NewConsoleEncoder(encCfg)
}

func newSink(opts Options) (zapcore.WriteSyncer, func() error, error) {
	switch strings.ToLower(strings.TrimSpace(opts.Output)) {
	case "stdout":
		return zapcore.AddSync(os.Stdout), nil, nil
	case "stderr", "":
		return zapcore.AddSync(os.Stderr), nil, nil
	case "file":
		if strings.TrimSpace(opts.File) == "" {
			return nil, nil, fmt.Errorf("log.file is required when log.output=file")
		}
		f, err := os.OpenFile(opts.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, nil, err
		}
		return zapcore.AddSync(f), f.Close, nil
	default:
		return nil, nil, fmt.Errorf("invalid log output: %q", opts.Output)
	}
}

func Nop() Logger {
	return &zapLogger{base: zap.NewNop()}
}

