package diagnostics

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readArchive(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	files := make(map[string][]byte, len(reader.File))
	for _, file := range reader.File {
		handle, err := file.Open()
		require.NoError(t, err)
		content, err := io.ReadAll(handle)
		require.NoError(t, err)
		require.NoError(t, handle.Close())
		files[file.Name] = content
	}
	return files
}

func TestSupportBundleRequiresExplicitConsent(t *testing.T) {
	var buffer bytes.Buffer
	_, err := WriteSupportBundle(&buffer, BundleRequest{
		Snapshot: Snapshot{},
		Options:  BundleOptions{Consent: false},
	})

	require.ErrorIs(t, err, ErrConsentRequired)
	assert.Zero(t, buffer.Len(), "a refused bundle must not write anything")
}

func TestSupportBundleManifestMatchesPayload(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	var buffer bytes.Buffer
	manifest, err := WriteSupportBundle(&buffer, BundleRequest{
		Snapshot: Snapshot{
			GeneratedAt: now,
			Traffic:     AggregateTraffic(CounterSample{}),
		},
		Logs: []Record{{
			Time:    now,
			Level:   "INFO",
			Message: "policy applied",
		}},
		Extras: []ExtraFile{{Name: "notes.txt", Data: []byte("local note")}},
		Options: BundleOptions{
			Consent:  true,
			MaxBytes: 128 << 10,
			Now:      func() time.Time { return now },
		},
	})
	require.NoError(t, err)
	require.NotZero(t, buffer.Len())

	files := readArchive(t, buffer.Bytes())
	for _, name := range []string{readmeFileName, manifestFileName, diagnosticsFileName, logsFileName, "notes.txt"} {
		assert.Contains(t, files, name, "bundle must contain %s", name)
	}

	require.Equal(t, BundleSchemaVersion, manifest.SchemaVersion)
	assert.Equal(t, now, manifest.CreatedAt)
	assert.False(t, manifest.Truncated)
	assert.NotEmpty(t, manifest.PayloadSemantics)
	assert.NotEmpty(t, manifest.InterfaceSemantics)
	assert.NotEmpty(t, manifest.Redactions)

	var sawDiagnostics bool
	for _, file := range manifest.Files {
		content, ok := files[file.Name]
		require.True(t, ok, "manifest file %q must exist", file.Name)
		assert.Equal(t, int64(len(content)), file.Size, "size for %q", file.Name)
		sum := sha256.Sum256(content)
		assert.Equal(t, hex.EncodeToString(sum[:]), file.SHA256, "hash for %q", file.Name)
		if file.Name == diagnosticsFileName {
			sawDiagnostics = true
		}
	}
	assert.True(t, sawDiagnostics, "manifest must describe diagnostics.json")
}

func TestSupportBundleRemovesSensitiveArtifactsAndValues(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	snapshot := Snapshot{
		GeneratedAt: now,
		Apply: ApplyState{
			Available: true,
			LastError: "token=abc123 failed for /home/alice/netbird at 10.1.2.3 peer.example.com",
		},
	}
	logs := []Record{{
		Time:    now,
		Level:   "ERROR",
		Message: "connect 10.9.8.7 peer.example.net from /home/alice/bin/netbird token=logsecret",
		Fields: map[string]string{
			"token":   "fieldsecret",
			"peer_ip": "10.9.8.7",
		},
	}}

	var buffer bytes.Buffer
	manifest, err := WriteSupportBundle(&buffer, BundleRequest{
		Snapshot: snapshot,
		Logs:     logs,
		Extras: []ExtraFile{
			{Name: "dns_history.json", Data: []byte(`{"example.com":["10.0.0.1"]}`)},
			{Name: "resolved_domains.txt", Data: []byte("example.com")},
			{Name: "peer_ips.txt", Data: []byte("10.0.0.1")},
			{Name: "diagnostics.json", Data: []byte(`{"spoofed":true}`)},
			{Name: "notes.txt", Data: []byte("peer.example.com at 10.0.0.1 token=extrasecret")},
		},
		Options: BundleOptions{
			Consent:  true,
			MaxBytes: 256 << 10,
			Now:      func() time.Time { return now },
		},
	})
	require.NoError(t, err)

	files := readArchive(t, buffer.Bytes())
	for _, name := range []string{"dns_history.json", "resolved_domains.txt", "peer_ips.txt"} {
		assert.NotContains(t, files, name, "sensitive artifact %q must be removed", name)
	}

	all := string(files[diagnosticsFileName]) + string(files[logsFileName]) + string(files["notes.txt"])
	for _, secret := range []string{
		"abc123", "logsecret", "fieldsecret", "extrasecret",
		"10.1.2.3", "10.9.8.7", "10.0.0.1",
		"peer.example.com", "peer.example.net", "example.com",
		"/home/alice/netbird", "/home/alice/bin/netbird",
	} {
		assert.NotContains(t, all, secret, "bundle must not contain %q", secret)
	}

	excluded := make(map[string]string)
	for _, item := range manifest.Excluded {
		excluded[item.Name] = item.Reason
	}
	assert.Contains(t, excluded, "dns_history.json")
	assert.Contains(t, excluded, "resolved_domains.txt")
	assert.Contains(t, excluded, "diagnostics.json")
}

func TestSupportBundleEnforcesSizeLimit(t *testing.T) {
	now := time.Unix(300, 0).UTC()
	random := rand.New(rand.NewSource(7))
	logs := make([]Record, 0, 4000)
	for i := 0; i < 4000; i++ {
		message := make([]byte, 256)
		random.Read(message)
		logs = append(logs, Record{
			Time:    now,
			Level:   "INFO",
			Message: fmt.Sprintf("%d %x", i, message),
		})
	}

	const maxBytes = 32 << 10
	var buffer bytes.Buffer
	manifest, err := WriteSupportBundle(&buffer, BundleRequest{
		Snapshot: Snapshot{GeneratedAt: now},
		Logs:     logs,
		Options: BundleOptions{
			Consent:  true,
			MaxBytes: maxBytes,
			Now:      func() time.Time { return now },
		},
	})
	require.NoError(t, err)
	assert.LessOrEqual(t, int64(buffer.Len()), int64(maxBytes), "archive must respect the limit")
	assert.True(t, manifest.Truncated, "the writer must document truncated logs")
}

func TestSupportBundleRejectsImpossibleSizeLimit(t *testing.T) {
	var buffer bytes.Buffer
	_, err := WriteSupportBundle(&buffer, BundleRequest{
		Snapshot: Snapshot{},
		Options: BundleOptions{
			Consent:  true,
			MaxBytes: 64,
		},
	})
	require.ErrorIs(t, err, ErrBundleTooLarge)
	assert.Zero(t, buffer.Len())
}

func TestSupportBundleDropsOversizedExtras(t *testing.T) {
	now := time.Unix(400, 0).UTC()
	var buffer bytes.Buffer
	manifest, err := WriteSupportBundle(&buffer, BundleRequest{
		Snapshot: Snapshot{GeneratedAt: now},
		Extras: []ExtraFile{{
			Name: "large.txt",
			Data: []byte(strings.Repeat("x", 4096)),
		}},
		Options: BundleOptions{
			Consent:  true,
			MaxBytes: 8 << 10,
			Now:      func() time.Time { return now },
		},
	})
	require.NoError(t, err)
	assert.LessOrEqual(t, int64(buffer.Len()), int64(8<<10))
	if manifest.Truncated {
		assert.NotEmpty(t, manifest.Excluded)
	}
}
