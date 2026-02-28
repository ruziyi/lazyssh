// Copyright 2025.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ssh_config_file

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Adembc/lazyssh/internal/core/domain"
	"go.uber.org/zap"
)

func TestListServersIncludeAndMainPriority(t *testing.T) {
	tmp := t.TempDir()
	mainPath := filepath.Join(tmp, "config")
	includePath := filepath.Join(tmp, "include.conf")
	metaPath := filepath.Join(tmp, "metadata", "metadata.json")

	writeTestFile(t, includePath, `Host include-only
    HostName 10.0.0.2
    User include

Host shared
    HostName 10.0.0.3
    User include
`)

	writeTestFile(t, mainPath, "Host main-only\n    HostName 10.0.0.1\n    User main\n\nInclude "+includePath+"\n\nHost shared\n    HostName 127.0.0.1\n    User main\n")

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

	if len(servers) != 3 {
		t.Fatalf("expected 3 servers, got %d", len(servers))
	}

	byAlias := make(map[string]domain.Server, len(servers))
	for _, s := range servers {
		byAlias[s.Alias] = s
	}

	if _, ok := byAlias["main-only"]; !ok {
		t.Fatalf("expected main-only alias to exist")
	}
	if _, ok := byAlias["include-only"]; !ok {
		t.Fatalf("expected include-only alias to exist")
	}
	shared, ok := byAlias["shared"]
	if !ok {
		t.Fatalf("expected shared alias to exist")
	}

	if shared.SourceFile != mainPath {
		t.Fatalf("expected shared to come from main config, got %s", shared.SourceFile)
	}
	if shared.Host != "127.0.0.1" {
		t.Fatalf("expected shared host from main config, got %s", shared.Host)
	}

	includeOnly := byAlias["include-only"]
	if includeOnly.SourceFile != includePath {
		t.Fatalf("expected include-only source to be include file, got %s", includeOnly.SourceFile)
	}
}

func TestListServersIncludeWithTildePath(t *testing.T) {
	tmp := t.TempDir()
	mainPath := filepath.Join(tmp, "config")
	metaPath := filepath.Join(tmp, "metadata", "metadata.json")

	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	includeDir := filepath.Join(homeDir, "includes")
	if err := os.MkdirAll(includeDir, 0o755); err != nil {
		t.Fatalf("failed to create include dir: %v", err)
	}

	includePath := filepath.Join(includeDir, "tilde.conf")
	writeTestFile(t, includePath, `Host tilde-only
    HostName 10.10.10.10
    User tilde
`)

	relIncludePath, err := filepath.Rel(homeDir, includePath)
	if err != nil {
		t.Fatalf("failed to compute include path relative to home: %v", err)
	}

	includeDirective := "~/" + filepath.ToSlash(relIncludePath)
	writeTestFile(t, mainPath, "Include "+includeDirective+"\n")

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
		t.Fatalf("expected 1 server from tilde include, got %d", len(servers))
	}
	if servers[0].Alias != "tilde-only" {
		t.Fatalf("expected alias tilde-only, got %s", servers[0].Alias)
	}
	if filepath.Clean(servers[0].SourceFile) != filepath.Clean(includePath) {
		t.Fatalf("expected source file %s, got %s", includePath, servers[0].SourceFile)
	}
}

func TestUpdateServerFromIncludeWritesIncludeFileAndBackups(t *testing.T) {
	tmp := t.TempDir()
	mainPath := filepath.Join(tmp, "config")
	includePath := filepath.Join(tmp, "include.conf")
	metaPath := filepath.Join(tmp, "metadata", "metadata.json")

	writeTestFile(t, includePath, `Host inc-edit
    HostName 10.2.0.1
    User include
`)
	writeTestFile(t, mainPath, "Include "+includePath+"\n")

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

	original := servers[0]
	updated := original
	updated.Host = "10.9.9.9"
	updated.User = "changed"

	if err := repo.UpdateServer(original, updated); err != nil {
		t.Fatalf("UpdateServer failed: %v", err)
	}

	includeContent := readTestFile(t, includePath)
	if !strings.Contains(includeContent, "HostName 10.9.9.9") {
		t.Fatalf("expected include file to contain updated host, content:\n%s", includeContent)
	}
	if !strings.Contains(includeContent, "User changed") {
		t.Fatalf("expected include file to contain updated user, content:\n%s", includeContent)
	}

	mainContent := readTestFile(t, mainPath)
	if strings.Contains(mainContent, "10.9.9.9") {
		t.Fatalf("expected main config to remain unchanged, content:\n%s", mainContent)
	}

	if _, err := os.Stat(filepath.Join(tmp, "include.conf.original.backup")); err != nil {
		t.Fatalf("expected include original backup to exist: %v", err)
	}
	rolling, err := filepath.Glob(includePath + "-*-" + BackupSuffix)
	if err != nil {
		t.Fatalf("glob backup files failed: %v", err)
	}
	if len(rolling) == 0 {
		t.Fatalf("expected include rolling backup to exist")
	}
}

func TestAddServerTargetFileAndGlobalAliasUniqueness(t *testing.T) {
	tmp := t.TempDir()
	mainPath := filepath.Join(tmp, "config")
	includePath := filepath.Join(tmp, "include.conf")
	metaPath := filepath.Join(tmp, "metadata", "metadata.json")

	writeTestFile(t, includePath, `Host in-include
    HostName 192.168.1.10
    User include
`)
	writeTestFile(t, mainPath, "Include "+includePath+"\n")

	repo := &Repository{
		configPath:      mainPath,
		fileSystem:      DefaultFileSystem{},
		metadataManager: newMetadataManager(metaPath, zap.NewNop().Sugar()),
		logger:          zap.NewNop().Sugar(),
	}

	newSrv := domain.Server{
		Alias: "added-into-include",
		Host:  "172.16.0.20",
		User:  "tester",
		Port:  22,
	}
	if err := repo.AddServer(newSrv, includePath); err != nil {
		t.Fatalf("AddServer to include file failed: %v", err)
	}

	includeContent := readTestFile(t, includePath)
	if !strings.Contains(includeContent, "Host added-into-include") {
		t.Fatalf("expected include file to contain newly added host, content:\n%s", includeContent)
	}

	conflict := domain.Server{Alias: "in-include", Host: "8.8.8.8", User: "dup"}
	if err := repo.AddServer(conflict, mainPath); err == nil {
		t.Fatalf("expected global alias conflict error, got nil")
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir failed for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write failed for %s: %v", path, err)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read failed for %s: %v", path, err)
	}
	return string(b)
}
