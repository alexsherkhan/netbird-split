package diagnostics

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
)

const (
	// BundleSchemaVersion is the support bundle manifest version.
	BundleSchemaVersion = 1
	// DefaultMaxBundleBytes bounds a support bundle. The caller may lower or
	// raise it, but the writer always enforces the selected limit.
	DefaultMaxBundleBytes int64 = 1 << 20
	maxBundleLogBytes     int64 = 256 << 10
	maxBundleExtraBytes   int64 = 64 << 10
)

var (
	// ErrConsentRequired reports a bundle request without explicit consent.
	ErrConsentRequired = errors.New("support bundle requires explicit consent")
	// ErrBundleTooLarge reports that even an empty bundle exceeds the limit.
	ErrBundleTooLarge = errors.New("support bundle exceeds its size limit")
)

const manifestFileName = "manifest.json"
const readmeFileName = "README.txt"
const diagnosticsFileName = "diagnostics.json"
const logsFileName = "logs.jsonl"

const bundleReadme = `Split tunnel support bundle

This bundle was written locally after explicit consent. It was not uploaded and
no background process will send it anywhere. Share it only with someone you
trust.

Manifest
manifest.json lists every payload file with its size and SHA-256 hash, the
artifacts that were excluded because they are sensitive, the redactions applied,
and the size limit enforced while writing the bundle.

Payload versus interface byte semantics
The outgoing byte counter is the IP payload seen by the owned split tunnel
classification rules. It excludes link-layer framing and interface overhead, so
it is not the same value as a network interface counter such as
/sys/class/net/<iface>/statistics/tx_bytes. VPN, DIRECT, BLOCK and EXIT totals
are disjoint: a packet matches one classification rule, so the class totals add
up to the outgoing total. Rule hits count matched packets, not bytes. Incoming
bytes and active connections are reported as unavailable because the owned
counters observe egress only.

Redaction
Secrets, credentials, private keys, IP addresses, host names, DNS history, user
paths and executable paths are removed before a file enters the bundle. DNS
history artifacts and other sensitive file names are excluded entirely. The
counters and state in diagnostics.json carry no addresses or peer identities.

Files
README.txt          This document.
manifest.json       Machine-readable manifest.
diagnostics.json    Redacted point-in-time counters and state.
logs.jsonl          Retained structured log records, redacted and bounded.
`

// ExtraFile is one caller-supplied text artifact.
type ExtraFile struct {
	Name string
	Data []byte
}

// BundleOptions configures a bundle write.
type BundleOptions struct {
	// Consent must be true. The writer never assumes consent.
	Consent bool
	// MaxBytes bounds the archive size. A non-positive value uses the default.
	MaxBytes int64
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// BundleRequest is one support bundle write.
type BundleRequest struct {
	Snapshot Snapshot
	Logs     []Record
	Extras   []ExtraFile
	Options  BundleOptions
}

// ManifestFile describes one included file.
type ManifestFile struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ExcludedArtifact records a file that was refused.
type ExcludedArtifact struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// Manifest documents the payload and the redactions of one bundle.
type Manifest struct {
	SchemaVersion      int                `json:"schemaVersion"`
	CreatedAt          time.Time          `json:"createdAt"`
	MaxBytes           int64              `json:"maxBytes"`
	Files              []ManifestFile     `json:"files"`
	Excluded           []ExcludedArtifact `json:"excluded,omitempty"`
	Truncated          bool               `json:"truncated"`
	Redactions         []string           `json:"redactions"`
	PayloadSemantics   string             `json:"payloadSemantics"`
	InterfaceSemantics string             `json:"interfaceSemantics"`
}

type bundleEntry struct {
	name string
	kind string
	data []byte
}

// WriteSupportBundle writes a redacted zip archive to w and returns its
// manifest. It returns ErrConsentRequired without explicit consent and never
// uploads the archive.
func WriteSupportBundle(w io.Writer, request BundleRequest) (Manifest, error) {
	if !request.Options.Consent {
		return Manifest{}, ErrConsentRequired
	}
	maxBytes := request.Options.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBundleBytes
	}
	now := request.Options.Now
	if now == nil {
		now = time.Now
	}
	createdAt := now().UTC()

	snapshot := RedactSnapshot(request.Snapshot)
	diagnosticsData, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return Manifest{}, fmt.Errorf("encode diagnostics: %w", err)
	}
	logs := sanitizeLogs(request.Logs)
	extras, excluded := sanitizeExtras(request.Extras)

	truncated := false
	for {
		entries := []bundleEntry{
			{name: diagnosticsFileName, kind: "diagnostics", data: diagnosticsData},
		}
		if len(logs) > 0 {
			logsData, err := encodeLogs(logs)
			if err != nil {
				return Manifest{}, err
			}
			entries = append(entries, bundleEntry{name: logsFileName, kind: "logs", data: logsData})
		}
		entries = append(entries, extras...)

		manifest := newManifest(createdAt, maxBytes, entries, excluded, truncated)
		archive, err := encodeArchive(createdAt, entries, manifest)
		if err != nil {
			return Manifest{}, err
		}
		if int64(len(archive)) <= maxBytes {
			if _, err := w.Write(archive); err != nil {
				return Manifest{}, fmt.Errorf("write support bundle: %w", err)
			}
			return manifest, nil
		}

		switch {
		case len(logs) > 0:
			logs = logs[len(logs)/2:]
			truncated = true
		case len(extras) > 0:
			excluded = append(excluded, ExcludedArtifact{
				Name:   extras[len(extras)-1].name,
				Reason: "removed to satisfy the bundle size limit",
			})
			extras = extras[:len(extras)-1]
			truncated = true
		default:
			return Manifest{}, ErrBundleTooLarge
		}
	}
}

func newManifest(
	createdAt time.Time,
	maxBytes int64,
	entries []bundleEntry,
	excluded []ExcludedArtifact,
	truncated bool,
) Manifest {
	files := make([]ManifestFile, 0, len(entries)+1)
	for _, entry := range entries {
		files = append(files, manifestFile(entry))
	}
	files = append(files, manifestFile(bundleEntry{
		name: readmeFileName,
		kind: "documentation",
		data: []byte(bundleReadme),
	}))
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return Manifest{
		SchemaVersion: BundleSchemaVersion,
		CreatedAt:     createdAt,
		MaxBytes:      maxBytes,
		Files:         files,
		Excluded:      excluded,
		Truncated:     truncated,
		Redactions: []string{
			"secrets and credentials",
			"private keys",
			"IP addresses",
			"host names and DNS history",
			"user paths",
			"executable paths",
		},
		PayloadSemantics: "outgoing bytes are IP payload bytes counted by owned " +
			"classification rules and exclude link-layer overhead",
		InterfaceSemantics: "interface counters include framing and other traffic and " +
			"are not used for VPN, DIRECT or BLOCK totals",
	}
}

func manifestFile(entry bundleEntry) ManifestFile {
	sum := sha256.Sum256(entry.data)
	return ManifestFile{
		Name:   entry.name,
		Kind:   entry.kind,
		Size:   int64(len(entry.data)),
		SHA256: hex.EncodeToString(sum[:]),
	}
}

func encodeArchive(createdAt time.Time, entries []bundleEntry, manifest Manifest) ([]byte, error) {
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode bundle manifest: %w", err)
	}
	all := make([]bundleEntry, 0, len(entries)+2)
	all = append(all,
		bundleEntry{name: readmeFileName, kind: "documentation", data: []byte(bundleReadme)},
		bundleEntry{name: manifestFileName, kind: "manifest", data: manifestData},
	)
	all = append(all, entries...)
	sort.SliceStable(all, func(i, j int) bool { return all[i].name < all[j].name })

	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for _, entry := range all {
		header := &zip.FileHeader{
			Name:     entry.name,
			Method:   zip.Deflate,
			Modified: createdAt,
		}
		writer, err := archive.CreateHeader(header)
		if err != nil {
			return nil, fmt.Errorf("create bundle entry %q: %w", entry.name, err)
		}
		if _, err := writer.Write(entry.data); err != nil {
			return nil, fmt.Errorf("write bundle entry %q: %w", entry.name, err)
		}
	}
	if err := archive.Close(); err != nil {
		return nil, fmt.Errorf("close support bundle: %w", err)
	}
	return buffer.Bytes(), nil
}

func sanitizeLogs(records []Record) []Record {
	if len(records) == 0 {
		return nil
	}
	out := make([]Record, 0, len(records))
	var total int64
	for _, record := range records {
		if total >= maxBundleLogBytes {
			break
		}
		redacted := Record{
			Time:    record.Time.UTC(),
			Level:   record.Level,
			Message: truncate(RedactText(record.Message), maxLogMessageBytes),
			Fields:  RedactFields(record.Fields, true),
		}
		size := int64(len(redacted.Message))
		for key, value := range redacted.Fields {
			size += int64(len(key) + len(value))
		}
		if total+size > maxBundleLogBytes {
			break
		}
		total += size
		out = append(out, redacted)
	}
	return out
}

func encodeLogs(records []Record) ([]byte, error) {
	var buffer bytes.Buffer
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			return nil, fmt.Errorf("encode log record: %w", err)
		}
		buffer.Write(line)
		buffer.WriteByte('\n')
	}
	return buffer.Bytes(), nil
}

func sanitizeExtras(extras []ExtraFile) ([]bundleEntry, []ExcludedArtifact) {
	entries := make([]bundleEntry, 0, len(extras))
	var excluded []ExcludedArtifact
	seen := make(map[string]struct{}, len(extras))
	for _, extra := range extras {
		name := artifactName(extra.Name)
		if name == "" {
			excluded = append(excluded, ExcludedArtifact{
				Name:   extra.Name,
				Reason: "invalid artifact name",
			})
			continue
		}
		if isSensitiveArtifact(name) {
			excluded = append(excluded, ExcludedArtifact{
				Name:   name,
				Reason: "sensitive artifact is never included",
			})
			continue
		}
		if isReservedArtifact(name) {
			excluded = append(excluded, ExcludedArtifact{
				Name:   name,
				Reason: "reserved bundle file name",
			})
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			excluded = append(excluded, ExcludedArtifact{
				Name:   name,
				Reason: "duplicate artifact name",
			})
			continue
		}
		if bytes.IndexByte(extra.Data, 0) >= 0 {
			excluded = append(excluded, ExcludedArtifact{
				Name:   name,
				Reason: "binary artifact is not included",
			})
			continue
		}
		data := []byte(RedactText(string(extra.Data)))
		if int64(len(data)) > maxBundleExtraBytes {
			data = data[:maxBundleExtraBytes]
		}
		seen[name] = struct{}{}
		entries = append(entries, bundleEntry{name: name, kind: "extra", data: data})
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	return entries, excluded
}

func artifactName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	base := path.Base(strings.ReplaceAll(raw, "\\", "/"))
	if base == "." || base == ".." || base == "/" {
		return ""
	}
	if strings.ContainsAny(base, "\x00") {
		return ""
	}
	return base
}

func isReservedArtifact(name string) bool {
	switch name {
	case readmeFileName, manifestFileName, diagnosticsFileName, logsFileName:
		return true
	default:
		return false
	}
}

func isSensitiveArtifact(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range []string{
		"dns_history", "dns-history", "dnshistory",
		"resolved_domains", "resolved-domains",
		"peer_ip", "peer-ip", "peer_ips", "peer-ips",
		"secret", "token", "credential", "password",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
