package diagnostics

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedactSecretsRemovesCredentialValues(t *testing.T) {
	input := strings.Join([]string{
		`token=abc123`,
		`password: hunter2`,
		`api_key = "top-secret"`,
		`Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature`,
		"-----BEGIN OPENSSH PRIVATE KEY-----\nMIIEsecret\n-----END OPENSSH PRIVATE KEY-----",
	}, "\n")

	redacted := RedactSecrets(input)

	for _, secret := range []string{"abc123", "hunter2", "top-secret", "eyJhbGciOiJIUzI1NiJ9", "MIIEsecret"} {
		assert.NotContains(t, redacted, secret)
	}
	assert.Contains(t, redacted, redactedSecret)
}

func TestRedactTextRemovesPathsAddressesAndHosts(t *testing.T) {
	input := strings.Join([]string{
		"/home/alice/notes.txt",
		"C:\\Users\\bob\\AppData\\app.exe",
		"10.1.2.3",
		"2001:db8::1",
		"peer.example.com",
	}, " ")

	redacted := RedactText(input)

	for _, value := range []string{
		"/home/alice/notes.txt",
		"alice",
		"bob",
		"app.exe",
		"10.1.2.3",
		"2001:db8::1",
		"peer.example.com",
	} {
		assert.NotContains(t, redacted, value)
	}
	assert.Contains(t, redacted, redactedPath)
	assert.Contains(t, redacted, redactedIP)
	assert.Contains(t, redacted, redactedHost)
}

func TestRedactLogTextKeepsPeerAddressesAtDebug(t *testing.T) {
	input := "peer 10.0.0.5 at peer.example.com opened /home/alice/file"

	debug := RedactLogText(LevelDebug, input)
	assert.Contains(t, debug, "10.0.0.5", "DEBUG may keep a peer address for local debugging")
	assert.Contains(t, debug, "peer.example.com")
	assert.NotContains(t, debug, "/home/alice/file", "paths are always removed")
	assert.Contains(t, debug, redactedPath)

	info := RedactLogText(LevelInfo, input)
	assert.NotContains(t, info, "10.0.0.5")
	assert.NotContains(t, info, "peer.example.com")
	assert.Contains(t, info, redactedIP)
	assert.Contains(t, info, redactedHost)
}

func TestRedactLogTextRemovesSecretsAtEveryLevel(t *testing.T) {
	input := "token=abc123 /home/alice/file"

	for _, level := range []Level{LevelTrace, LevelDebug, LevelInfo, LevelWarn, LevelError} {
		redacted := RedactLogText(level, input)
		assert.NotContains(t, redacted, "abc123", "level %s", level)
		assert.NotContains(t, redacted, "/home/alice/file", "level %s", level)
	}
}

func TestSecretFieldNameMatchesCredentialKeys(t *testing.T) {
	for _, name := range []string{"token", "api_key", "Authorization", "private-key", "PASSWORD"} {
		assert.True(t, SecretFieldName(name), "field %q must be treated as a secret", name)
	}
	for _, name := range []string{"peer", "interface", "bytes"} {
		assert.False(t, SecretFieldName(name), "field %q is not a secret", name)
	}
}

func TestRedactFieldsMasksSecretKeys(t *testing.T) {
	fields := RedactFields(map[string]string{
		"token":   "abc123",
		"peer_ip": "10.0.0.5",
		"note":    "peer.example.com",
	}, true)

	assert.Equal(t, redactedSecret, fields["token"])
	assert.NotContains(t, fields["peer_ip"], "10.0.0.5")
	assert.NotContains(t, fields["note"], "peer.example.com")
}

func TestRedactSnapshotSanitizesFreeFormState(t *testing.T) {
	snapshot := Snapshot{
		Apply:      ApplyState{LastError: "token=abc at /home/alice/file"},
		Gateway:    GatewayState{BackendState: "peer 10.0.0.5"},
		KillSwitch: KillSwitchState{LastEvent: "peer.example.com"},
	}

	redacted := RedactSnapshot(snapshot)

	assert.NotContains(t, redacted.Apply.LastError, "abc")
	assert.NotContains(t, redacted.Apply.LastError, "/home/alice/file")
	assert.NotContains(t, redacted.Gateway.BackendState, "10.0.0.5")
	assert.NotContains(t, redacted.KillSwitch.LastEvent, "peer.example.com")
}
