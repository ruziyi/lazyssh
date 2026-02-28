package ssh_config_file

import (
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestListServers_MergeIPLocationMetadata(t *testing.T) {
	tmp := t.TempDir()
	mainPath := filepath.Join(tmp, "config")
	metaPath := filepath.Join(tmp, "metadata", "metadata.json")

	writeTestFile(t, mainPath, `Host geo
    HostName 8.8.8.8
    User root
`)

	if err := os.MkdirAll(filepath.Dir(metaPath), 0o755); err != nil {
		t.Fatalf("mkdir metadata dir failed: %v", err)
	}
	metadataJSON := `{
  "geo": {
    "resolved_ip": "8.8.8.8",
    "ip_location_short": "US/CA",
    "ip_location_updated_at": "2026-02-28T12:00:00Z"
  }
}`
	if err := os.WriteFile(metaPath, []byte(metadataJSON), 0o600); err != nil {
		t.Fatalf("write metadata file failed: %v", err)
	}

	repo := &Repository{
		configPath:      mainPath,
		fileSystem:      DefaultFileSystem{},
		metadataManager: newMetadataManager(metaPath, zap.NewNop().Sugar()),
		logger:          zap.NewNop().Sugar(),
	}

	servers, err := repo.ListServers("")
	if err != nil {
		t.Fatalf("ListServers failed: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}

	s := servers[0]
	if s.ResolvedIP != "8.8.8.8" {
		t.Fatalf("expected resolved_ip 8.8.8.8, got %q", s.ResolvedIP)
	}
	if s.IPLocationShort != "US/CA" {
		t.Fatalf("expected ip location US/CA, got %q", s.IPLocationShort)
	}
	if s.IPLocationUpdatedAt.IsZero() {
		t.Fatalf("expected non-zero IPLocationUpdatedAt")
	}
}
