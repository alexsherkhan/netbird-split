package diagnostics

import (
	"strings"
	"sync"
	"time"
)

const (
	// DefaultMaxLogRecords bounds the retained log history.
	DefaultMaxLogRecords = 1000
	maxLogMessageBytes   = 8 << 10
	maxLogFieldBytes     = 1 << 10
)

// Level is a structured log severity. The numeric order matches severity, so a
// logger can filter every record below its configured minimum.
type Level int

const (
	// LevelTrace is the most verbose level, used for packet-level debugging.
	LevelTrace Level = iota
	// LevelDebug is for local development diagnostics.
	LevelDebug
	// LevelInfo is the default operational level.
	LevelInfo
	// LevelWarn reports a recoverable degradation.
	LevelWarn
	// LevelError reports a failed operation.
	LevelError
)

// String returns the stable name used in JSON output.
func (l Level) String() string {
	switch l {
	case LevelTrace:
		return "TRACE"
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// ParseLevel parses a stable level name case-insensitively.
func ParseLevel(value string) (Level, bool) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "TRACE":
		return LevelTrace, true
	case "DEBUG":
		return LevelDebug, true
	case "INFO":
		return LevelInfo, true
	case "WARN", "WARNING":
		return LevelWarn, true
	case "ERROR":
		return LevelError, true
	default:
		return LevelInfo, false
	}
}

// Record is one retained structured log entry.
type Record struct {
	Time    time.Time         `json:"time"`
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
}

// LoggerOptions configures a bounded structured logger.
type LoggerOptions struct {
	// MaxRecords bounds retained history. A non-positive value uses
	// DefaultMaxLogRecords.
	MaxRecords int
	// MinLevel drops records below this severity.
	MinLevel Level
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// Logger keeps a bounded in-memory history of redacted structured records. It
// is intended for local support diagnostics, not for high-volume tracing.
type Logger struct {
	mu       sync.Mutex
	records  []Record
	max      int
	minLevel Level
	now      func() time.Time
}

// NewLogger returns a bounded logger.
func NewLogger(options LoggerOptions) *Logger {
	limit := options.MaxRecords
	if limit <= 0 {
		limit = DefaultMaxLogRecords
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Logger{
		records:  make([]Record, 0, limit),
		max:      limit,
		minLevel: options.MinLevel,
		now:      now,
	}
}

// Log records one message with structured fields. Secrets and paths are always
// redacted. Peer IP addresses and host names are redacted at INFO and above.
func (l *Logger) Log(level Level, message string, fields map[string]string) {
	if level < l.minLevel {
		return
	}
	record := Record{
		Time:    l.now().UTC(),
		Level:   level.String(),
		Message: truncate(RedactLogText(level, message), maxLogMessageBytes),
		Fields:  boundFields(RedactFields(fields, level >= LevelInfo)),
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, record)
	if len(l.records) > l.max {
		overflow := len(l.records) - l.max
		copy(l.records, l.records[overflow:])
		l.records = l.records[:l.max]
	}
}

// Trace records a TRACE message.
func (l *Logger) Trace(message string, fields map[string]string) {
	l.Log(LevelTrace, message, fields)
}

// Debug records a DEBUG message.
func (l *Logger) Debug(message string, fields map[string]string) {
	l.Log(LevelDebug, message, fields)
}

// Info records an INFO message.
func (l *Logger) Info(message string, fields map[string]string) {
	l.Log(LevelInfo, message, fields)
}

// Warn records a WARN message.
func (l *Logger) Warn(message string, fields map[string]string) {
	l.Log(LevelWarn, message, fields)
}

// Error records an ERROR message.
func (l *Logger) Error(message string, fields map[string]string) {
	l.Log(LevelError, message, fields)
}

// Records returns a copy of the retained history in insertion order.
func (l *Logger) Records() []Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Record, len(l.records))
	for i, record := range l.records {
		out[i] = record
		out[i].Fields = cloneFields(record.Fields)
	}
	return out
}

func boundFields(fields map[string]string) map[string]string {
	if len(fields) == 0 {
		return nil
	}
	out := make(map[string]string, len(fields))
	for key, value := range fields {
		out[truncate(key, 128)] = truncate(value, maxLogFieldBytes)
	}
	return out
}

func cloneFields(fields map[string]string) map[string]string {
	if len(fields) == 0 {
		return nil
	}
	out := make(map[string]string, len(fields))
	for key, value := range fields {
		out[key] = value
	}
	return out
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
