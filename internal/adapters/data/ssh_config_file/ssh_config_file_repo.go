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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Adembc/lazyssh/internal/core/domain"
	"github.com/Adembc/lazyssh/internal/core/ports"
	"github.com/kevinburke/ssh_config"
	"go.uber.org/zap"
)

// Repository implements ServerRepository interface for SSH config file operations.
type Repository struct {
	configPath      string
	fileSystem      FileSystem
	metadataManager *metadataManager
	logger          *zap.SugaredLogger
}

// NewRepository creates a new SSH config repository.
func NewRepository(logger *zap.SugaredLogger, configPath, metaDataPath string) ports.ServerRepository {
	return &Repository{
		logger:          logger,
		configPath:      configPath,
		fileSystem:      DefaultFileSystem{},
		metadataManager: newMetadataManager(metaDataPath, logger),
	}
}

// NewRepositoryWithFS creates a new SSH config repository with a custom filesystem.
func NewRepositoryWithFS(logger *zap.SugaredLogger, configPath string, metaDataPath string, fs FileSystem) ports.ServerRepository {
	return &Repository{
		logger:          logger,
		configPath:      configPath,
		fileSystem:      fs,
		metadataManager: newMetadataManager(metaDataPath, logger),
	}
}

// ListServers returns all servers matching the query pattern.
// Empty query returns all servers.
func (r *Repository) ListServers(query string) ([]domain.Server, error) {
	servers, err := r.listServersWithSource()
	if err != nil {
		return nil, fmt.Errorf("failed to list servers: %w", err)
	}

	metadata, err := r.metadataManager.loadAll()
	if err != nil {
		r.logger.Warnf("Failed to load metadata: %v", err)
		metadata = make(map[string]ServerMetadata)
	}
	servers = r.mergeMetadata(servers, metadata)
	if query == "" {
		return servers, nil
	}

	return r.filterServers(servers, query), nil
}

// ListConfigFiles returns the main SSH config file and all resolved Include files.
func (r *Repository) ListConfigFiles() ([]string, error) {
	mainCfg, err := r.loadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	files := []string{filepath.Clean(r.configPath)}
	visited := map[string]struct{}{
		filepath.Clean(r.configPath): {},
	}
	r.collectIncludeFiles(mainCfg, visited, &files)

	return files, nil
}

// AddServer adds a new server to the SSH config.
func (r *Repository) AddServer(server domain.Server, targetFile string) error {
	targetPath := r.resolveTargetFile(targetFile)

	cfg, err := r.loadConfigFromPath(targetPath)
	if err != nil {
		return fmt.Errorf("failed to load config %s: %w", targetPath, err)
	}

	exists, err := r.aliasExistsGlobal(server.Alias, "", "")
	if err != nil {
		return fmt.Errorf("failed to validate alias uniqueness: %w", err)
	}
	if exists {
		return fmt.Errorf("server with alias '%s' already exists", server.Alias)
	}

	host := r.createHostFromServer(server)
	cfg.Hosts = append(cfg.Hosts, host)

	if err := r.saveConfigToPath(targetPath, cfg); err != nil {
		r.logger.Warnf("Failed to save config while adding new server to %s: %v", targetPath, err)
		return fmt.Errorf("failed to save config: %w", err)
	}

	return r.metadataManager.updateServer(server, server.Alias)
}

// UpdateServer updates an existing server in the SSH config.
func (r *Repository) UpdateServer(server domain.Server, newServer domain.Server) error {
	sourcePath := r.resolveTargetFile(server.SourceFile)

	cfg, err := r.loadConfigFromPath(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to load config %s: %w", sourcePath, err)
	}

	host := r.findHostByAlias(cfg, server.Alias)
	if host == nil {
		return fmt.Errorf("server with alias '%s' not found", server.Alias)
	}

	if server.Alias != newServer.Alias {
		exists, err := r.aliasExistsGlobal(newServer.Alias, server.Alias, sourcePath)
		if err != nil {
			return fmt.Errorf("failed to validate alias uniqueness: %w", err)
		}
		if exists {
			return fmt.Errorf("server with alias '%s' already exists", newServer.Alias)
		}

		newPatterns := make([]*ssh_config.Pattern, 0, len(host.Patterns))
		for _, pattern := range host.Patterns {
			if pattern.Str == server.Alias {
				newPatterns = append(newPatterns, &ssh_config.Pattern{Str: newServer.Alias})
			} else {
				newPatterns = append(newPatterns, pattern)
			}
		}

		host.Patterns = newPatterns

	}

	r.updateHostNodes(host, newServer)

	if err := r.saveConfigToPath(sourcePath, cfg); err != nil {
		r.logger.Warnf("Failed to save config while updating server in %s: %v", sourcePath, err)
		return fmt.Errorf("failed to save config: %w", err)
	}
	// Update metadata; pass old alias to allow inline migration
	return r.metadataManager.updateServer(newServer, server.Alias)
}

// DeleteServer removes a server from the SSH config.
func (r *Repository) DeleteServer(server domain.Server) error {
	sourcePath := r.resolveTargetFile(server.SourceFile)

	cfg, err := r.loadConfigFromPath(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to load config %s: %w", sourcePath, err)
	}

	initialCount := len(cfg.Hosts)
	cfg.Hosts = r.removeHostByAlias(cfg.Hosts, server.Alias)

	if len(cfg.Hosts) == initialCount {
		return fmt.Errorf("server with alias '%s' not found", server.Alias)
	}

	if err := r.saveConfigToPath(sourcePath, cfg); err != nil {
		r.logger.Warnf("Failed to save config while deleting server from %s: %v", sourcePath, err)
		return fmt.Errorf("failed to save config: %w", err)
	}
	return r.metadataManager.deleteServer(server.Alias)
}

// SetPinned sets or unsets the pinned status of a server.
func (r *Repository) SetPinned(alias string, pinned bool) error {
	return r.metadataManager.setPinned(alias, pinned)
}

// RecordSSH increments the SSH access count and updates the last seen timestamp for a server.
func (r *Repository) RecordSSH(alias string) error {
	return r.metadataManager.recordSSH(alias)
}

func (r *Repository) UpdateIPLocationMetadata(updates map[string]domain.IPLocationCache) error {
	return r.metadataManager.updateIPLocations(updates)
}

func (r *Repository) resolveTargetFile(targetFile string) string {
	target := strings.TrimSpace(targetFile)
	if target == "" {
		return r.configPath
	}
	return filepath.Clean(target)
}

func (r *Repository) listServersWithSource() ([]domain.Server, error) {
	mainCfg, err := r.loadConfig()
	if err != nil {
		return nil, err
	}

	mainServers := r.toDomainServer(mainCfg, r.configPath)
	allServers := append([]domain.Server{}, mainServers...)

	visited := map[string]struct{}{filepath.Clean(r.configPath): {}}
	includeServers := r.collectIncludeServers(mainCfg, visited)
	allServers = append(allServers, includeServers...)

	seenAliases := make(map[string]struct{}, len(mainServers))
	deduped := make([]domain.Server, 0, len(allServers))

	for _, server := range allServers {
		if _, exists := seenAliases[server.Alias]; exists {
			continue
		}
		seenAliases[server.Alias] = struct{}{}
		deduped = append(deduped, server)
	}

	return deduped, nil
}

func (r *Repository) collectIncludeServers(cfg *ssh_config.Config, visited map[string]struct{}) []domain.Server {
	collected := make([]domain.Server, 0)

	for _, host := range cfg.Hosts {
		for _, node := range host.Nodes {
			includeNode, ok := node.(*ssh_config.Include)
			if !ok {
				continue
			}

			for _, included := range r.resolveIncludedConfigs(includeNode) {
				if included.Config == nil {
					continue
				}

				includePath := filepath.Clean(included.FilePath)
				if _, exists := visited[includePath]; exists {
					continue
				}
				visited[includePath] = struct{}{}

				collected = append(collected, r.toDomainServer(included.Config, includePath)...)
				collected = append(collected, r.collectIncludeServers(included.Config, visited)...)
			}
		}
	}

	return collected
}

func (r *Repository) collectIncludeFiles(cfg *ssh_config.Config, visited map[string]struct{}, files *[]string) {
	for _, host := range cfg.Hosts {
		for _, node := range host.Nodes {
			includeNode, ok := node.(*ssh_config.Include)
			if !ok {
				continue
			}
			for _, included := range r.resolveIncludedConfigs(includeNode) {
				if included.Config == nil {
					continue
				}
				includePath := filepath.Clean(included.FilePath)
				if _, exists := visited[includePath]; exists {
					continue
				}
				visited[includePath] = struct{}{}
				*files = append(*files, includePath)
				r.collectIncludeFiles(included.Config, visited, files)
			}
		}
	}
}

// resolveIncludedConfigs returns include entries parsed by ssh_config and also
// recovers Include paths using "~/" which ssh_config v1.4.0 does not resolve.
func (r *Repository) resolveIncludedConfigs(includeNode *ssh_config.Include) []ssh_config.IncludedConfig {
	resolved := make([]ssh_config.IncludedConfig, 0)
	seen := make(map[string]struct{})

	for _, included := range includeNode.IncludedConfigs() {
		if included.Config == nil {
			continue
		}
		includePath := filepath.Clean(included.FilePath)
		if _, exists := seen[includePath]; exists {
			continue
		}
		seen[includePath] = struct{}{}
		resolved = append(resolved, ssh_config.IncludedConfig{
			Config:   included.Config,
			FilePath: includePath,
		})
	}

	for _, pattern := range r.extractTildeIncludePatterns(includeNode.String()) {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			r.logger.Warnf("failed to glob include pattern %q: %v", pattern, err)
			continue
		}
		for _, match := range matches {
			includePath := filepath.Clean(match)
			if _, exists := seen[includePath]; exists {
				continue
			}
			cfg, err := r.loadConfigFromPath(includePath)
			if err != nil {
				r.logger.Warnf("failed to load include file %q: %v", includePath, err)
				continue
			}
			seen[includePath] = struct{}{}
			resolved = append(resolved, ssh_config.IncludedConfig{
				Config:   cfg,
				FilePath: includePath,
			})
		}
	}

	return resolved
}

func (r *Repository) extractTildeIncludePatterns(includeLine string) []string {
	line := strings.TrimSpace(includeLine)
	if line == "" {
		return nil
	}

	if idx := strings.Index(line, "#"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	if line == "" || !strings.HasPrefix(strings.ToLower(line), "include") {
		return nil
	}

	remainder := strings.TrimSpace(line[len("include"):])
	if strings.HasPrefix(remainder, "=") {
		remainder = strings.TrimSpace(remainder[1:])
	}
	if remainder == "" {
		return nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		r.logger.Warnf("failed to resolve user home for include line %q: %v", includeLine, err)
		return nil
	}

	tokens := strings.Fields(remainder)
	patterns := make([]string, 0, len(tokens))
	for _, token := range tokens {
		token = strings.Trim(token, `"'`)
		switch {
		case token == "~":
			patterns = append(patterns, homeDir)
		case strings.HasPrefix(token, "~/"):
			patterns = append(patterns, filepath.Join(homeDir, token[2:]))
		}
	}

	return patterns
}

func (r *Repository) aliasExistsGlobal(alias, excludeAlias, excludeSourceFile string) (bool, error) {
	mainCfg, err := r.loadConfig()
	if err != nil {
		return false, err
	}

	servers := r.toDomainServer(mainCfg, r.configPath)
	visited := map[string]struct{}{filepath.Clean(r.configPath): {}}
	servers = append(servers, r.collectIncludeServers(mainCfg, visited)...)

	excludeSource := filepath.Clean(excludeSourceFile)

	for _, server := range servers {
		if server.Alias != alias {
			continue
		}
		if excludeAlias != "" && server.Alias == excludeAlias && filepath.Clean(server.SourceFile) == excludeSource {
			continue
		}
		return true, nil
	}

	return false, nil
}
