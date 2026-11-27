package diagnostics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoggerBoundsRetention(t *testing.T) {
	logger := NewLogger(LoggerOptions{
		MaxRecords: 3,
		Now:        func() time.Time { return time.Unix(1, 0) },
	})

	for i := 0; i < 5; i++ {
		logger.Info("message", map[string]string{"index": string(rune('0' + i))})
	}

	records := logger.Records()
	require.Len(t, records, 3)
	assert.Equal(t, "2", records[0].Fields["index"], "oldest retained record must be the third")
	assert.Equal(t, "4", records[2].Fields["index"])
}

func TestLoggerFiltersBelowMinimumLevel(t *testing.T) {
	logger := NewLogger(LoggerOptions{MinLevel: LevelWarn})

	logger.Info("dropped", nil)
	logger.Warn("kept warn", nil)
	logger.Error("kept error", nil)

	records := logger.Records()
	require.Len(t, records, 2)
	assert.Equal(t, "WARN", records[0].Level)
	assert.Equal(t, "ERROR", records[1].Level)
}

func TestLoggerRedactsSecretsAndPeerAddressesByLevel(t *testing.T) {
	logger := NewLogger(LoggerOptions{MinLevel: LevelTrace})

	logger.Debug("peer 10.0.0.5 token=abc", map[string]string{
		"peer_ip": "10.0.0.5",
		"token":   "abc",
	})
	logger.Info("peer 10.0.0.5 token=abc", map[string]string{
		"peer_ip": "10.0.0.5",
		"note":    "peer.example.com",
	})

	records := logger.Records()
	require.Len(t, records, 2)

	assert.Contains(t, records[0].Message, "10.0.0.5", "DEBUG keeps peer addresses")
	assert.NotContains(t, records[0].Message, "abc")
	assert.Equal(t, redactedSecret, records[0].Fields["token"])
	assert.Contains(t, records[0].Fields["peer_ip"], "10.0.0.5")

	assert.NotContains(t, records[1].Message, "10.0.0.5", "INFO must not contain a peer address")
	assert.NotContains(t, records[1].Message, "abc")
	assert.NotContains(t, records[1].Fields["peer_ip"], "10.0.0.5")
	assert.NotContains(t, records[1].Fields["note"], "peer.example.com")
}

func TestLoggerTruncatesOversizedMessages(t *testing.T) {
	logger := NewLogger(LoggerOptions{})
	message := make([]byte, maxLogMessageBytes+100)
	for i := range message {
		message[i] = 'a'
	}

	logger.Info(string(message), nil)

	records := logger.Records()
	require.Len(t, records, 1)
	assert.Len(t, records[0].Message, maxLogMessageBytes)
}

func TestParseLevel(t *testing.T) {
	level, ok := ParseLevel("warn")
	assert.True(t, ok)
	assert.Equal(t, LevelWarn, level)

	level, ok = ParseLevel("TRACE")
	assert.True(t, ok)
	assert.Equal(t, LevelTrace, level)

	_, ok = ParseLevel("verbose")
	assert.False(t, ok)
}

func TestLevelString(t *testing.T) {
	assert.Equal(t, "TRACE", LevelTrace.String())
	assert.Equal(t, "DEBUG", LevelDebug.String())
	assert.Equal(t, "INFO", LevelInfo.String())
	assert.Equal(t, "WARN", LevelWarn.String())
	assert.Equal(t, "ERROR", LevelError.String())
	assert.Equal(t, "UNKNOWN", Level(99).String())
}
