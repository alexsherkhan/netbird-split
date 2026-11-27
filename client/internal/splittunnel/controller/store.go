package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

const (
	storeSchemaVersion uint32 = 1
	storeMaxBytes             = 64 << 20
)

// document is the on-disk container for the versioned split tunnel
// configuration. The configuration keeps its own schema version; this envelope
// adds the daemon-owned revision and the bounded rollback history.
type document struct {
	SchemaVersion uint32         `json:"schemaVersion"`
	Revision      uint64         `json:"revision"`
	Config        *config.Config `json:"config,omitempty"`
	History       []historyEntry `json:"history,omitempty"`
}

type historyEntry struct {
	Revision uint64         `json:"revision"`
	Config   *config.Config `json:"config"`
}

type wireDocument struct {
	SchemaVersion uint32             `json:"schemaVersion"`
	Revision      uint64             `json:"revision"`
	Config        json.RawMessage    `json:"config,omitempty"`
	History       []wireHistoryEntry `json:"history,omitempty"`
}

type wireHistoryEntry struct {
	Revision uint64          `json:"revision"`
	Config   json.RawMessage `json:"config"`
}

type store struct {
	path string
}

func newStore(path string) *store {
	return &store{path: path}
}

func (s *store) load() (document, error) {
	data, err := readLimited(s.path, storeMaxBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return document{SchemaVersion: storeSchemaVersion}, nil
		}
		return document{}, fmt.Errorf("read config file: %w", err)
	}

	var wire wireDocument
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		return document{}, fmt.Errorf("decode config file: %w", err)
	}
	if err := requireEOF(dec); err != nil {
		return document{}, err
	}
	return wire.toDocument()
}

func (w wireDocument) toDocument() (document, error) {
	if w.SchemaVersion != storeSchemaVersion {
		return document{}, fmt.Errorf("config file schema version %d is not supported", w.SchemaVersion)
	}

	doc := document{SchemaVersion: w.SchemaVersion, Revision: w.Revision}
	if len(w.Config) > 0 && string(w.Config) != "null" {
		cfg, err := config.Parse(w.Config)
		if err != nil {
			return document{}, fmt.Errorf("config: %w", err)
		}
		doc.Config = cfg
	}
	if doc.Config == nil && doc.Revision != 0 {
		return document{}, errors.New("config file has a revision without a configuration")
	}
	if doc.Config != nil && doc.Revision == 0 {
		return document{}, errors.New("config file has a configuration without a revision")
	}

	seen := map[uint64]struct{}{doc.Revision: {}}
	for i, item := range w.History {
		if len(item.Config) == 0 || string(item.Config) == "null" {
			return document{}, fmt.Errorf("history entry %d has no configuration", i)
		}
		cfg, err := config.Parse(item.Config)
		if err != nil {
			return document{}, fmt.Errorf("history entry %d: %w", i, err)
		}
		if item.Revision == 0 || item.Revision >= doc.Revision {
			return document{}, fmt.Errorf("history entry %d has invalid revision %d", i, item.Revision)
		}
		if _, ok := seen[item.Revision]; ok {
			return document{}, fmt.Errorf("history entry %d duplicates revision %d", i, item.Revision)
		}
		seen[item.Revision] = struct{}{}
		doc.History = append(doc.History, historyEntry{Revision: item.Revision, Config: cfg})
	}
	return doc, nil
}

func (s *store) save(doc document) error {
	if doc.SchemaVersion != storeSchemaVersion {
		return fmt.Errorf("refuse to write config file schema version %d", doc.SchemaVersion)
	}
	if doc.Config != nil && doc.Revision == 0 {
		return errors.New("refuse to write a configuration without a revision")
	}

	wire := wireDocument{SchemaVersion: doc.SchemaVersion, Revision: doc.Revision}
	if doc.Config != nil {
		encoded, err := doc.Config.Encode()
		if err != nil {
			return fmt.Errorf("encode config: %w", err)
		}
		wire.Config = encoded
	}
	for _, item := range doc.History {
		if item.Config == nil {
			return fmt.Errorf("history revision %d has no configuration", item.Revision)
		}
		encoded, err := item.Config.Encode()
		if err != nil {
			return fmt.Errorf("encode history revision %d: %w", item.Revision, err)
		}
		wire.History = append(wire.History, wireHistoryEntry{
			Revision: item.Revision,
			Config:   encoded,
		})
	}

	data, err := json.MarshalIndent(wire, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config file: %w", err)
	}
	data = append(data, '\n')
	return writeFileAtomic(s.path, data)
}

func readLimited(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("config file exceeds %d bytes", limit)
	}
	return data, nil
}

func requireEOF(dec *json.Decoder) error {
	var extra json.RawMessage
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("decode config file: %w", err)
	}
	return errors.New("config file has trailing data")
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".split-tunnel-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary config file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// After a successful rename the temporary file is gone, so this only
		// removes the staging file on a failure path.
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set config file permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write config file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync config file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close config file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace config file: %w", err)
	}
	return nil
}
