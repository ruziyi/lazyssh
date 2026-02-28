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

package services

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Adembc/lazyssh/internal/core/domain"
	"github.com/Adembc/lazyssh/internal/core/ports"
	"go.uber.org/zap"
)

const (
	defaultGeoIPBaseURL = "http://ip-api.com/json"
	defaultGeoIPWhois   = "https://ipwho.is"
	geoIPFields         = "status,countryCode,region,query,message"
	geoIPRequestTimeout = 1500 * time.Millisecond
	geoIPCacheTTL       = 24 * time.Hour
	geoIPConcurrency    = 5
)

type serverService struct {
	serverRepository ports.ServerRepository
	logger           *zap.SugaredLogger

	httpClient        *http.Client
	directHTTPClient  *http.Client
	geoIPBaseURL      string
	geoIPWhoisBaseURL string
	now               func() time.Time
	lookupIP          func(host string) ([]net.IP, error)

	fwMu     sync.Mutex
	forwards map[string][]*os.Process
}

// NewServerService creates a new instance of serverService.
func NewServerService(logger *zap.SugaredLogger, sr ports.ServerRepository) ports.ServerService {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil

	return &serverService{
		logger:            logger,
		serverRepository:  sr,
		httpClient:        &http.Client{Timeout: geoIPRequestTimeout},
		directHTTPClient:  &http.Client{Timeout: geoIPRequestTimeout, Transport: transport},
		geoIPBaseURL:      defaultGeoIPBaseURL,
		geoIPWhoisBaseURL: defaultGeoIPWhois,
		now:               time.Now,
		lookupIP:          net.LookupIP,
	}
}

// ListServers returns a list of servers sorted with pinned on top.
func (s *serverService) ListServers(query string) ([]domain.Server, error) {
	servers, err := s.serverRepository.ListServers(query)
	if err != nil {
		s.logger.Errorw("failed to list servers", "error", err)
		return nil, err
	}

	// Sort: pinned first (PinnedAt non-zero), then by PinnedAt desc, then by Alias asc.
	sort.SliceStable(servers, func(i, j int) bool {
		pi := !servers[i].PinnedAt.IsZero()
		pj := !servers[j].PinnedAt.IsZero()
		if pi != pj {
			return pi
		}
		if pi && pj {
			return servers[i].PinnedAt.After(servers[j].PinnedAt)
		}
		return servers[i].Alias < servers[j].Alias
	})

	return servers, nil
}

func (s *serverService) EnrichIPLocation(servers []domain.Server) ([]domain.Server, error) {
	if len(servers) == 0 {
		return servers, nil
	}

	enriched := append([]domain.Server(nil), servers...)
	updates := make(map[string]domain.IPLocationCache)
	var updateMu sync.Mutex
	var failMu sync.Mutex
	failCount := 0
	var firstErr error

	sem := make(chan struct{}, geoIPConcurrency)
	var wg sync.WaitGroup
	now := s.now()

	for i := range enriched {
		server := enriched[i]
		if strings.TrimSpace(server.Alias) == "" {
			continue
		}

		wg.Add(1)
		go func(idx int, srv domain.Server) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			cache, ok, resolveErr := s.resolveIPLocationCache(srv, now)
			if resolveErr != nil {
				s.logger.Debugw("resolve ip location failed", "alias", srv.Alias, "error", resolveErr)
				failMu.Lock()
				failCount++
				if firstErr == nil {
					firstErr = resolveErr
				}
				failMu.Unlock()
			}
			if !ok {
				return
			}

			updateMu.Lock()
			enriched[idx].ResolvedIP = cache.ResolvedIP
			enriched[idx].IPLocationShort = cache.IPLocationShort
			enriched[idx].IPLocationUpdatedAt = cache.IPLocationUpdatedAt
			updates[srv.Alias] = cache
			updateMu.Unlock()
		}(i, server)
	}

	wg.Wait()
	if len(updates) == 0 {
		if failCount > 0 {
			return enriched, fmt.Errorf("ip location update failed for %d servers: %w", failCount, firstErr)
		}
		return enriched, nil
	}

	if err := s.serverRepository.UpdateIPLocationMetadata(updates); err != nil {
		s.logger.Warnw("failed to persist ip location metadata", "error", err, "count", len(updates))
		return enriched, err
	}

	if failCount > 0 {
		return enriched, fmt.Errorf("ip location partially updated, failed: %d, first error: %w", failCount, firstErr)
	}

	return enriched, nil
}

func (s *serverService) ListConfigFiles() ([]string, error) {
	files, err := s.serverRepository.ListConfigFiles()
	if err != nil {
		s.logger.Errorw("failed to list config files", "error", err)
		return nil, err
	}
	return files, nil
}

// validateServer performs core validation of server fields.
func validateServer(srv domain.Server) error {
	if strings.TrimSpace(srv.Alias) == "" {
		return fmt.Errorf("alias is required")
	}
	if ok, _ := regexp.MatchString(`^[A-Za-z0-9_.-]+$`, srv.Alias); !ok {
		return fmt.Errorf("alias may contain letters, digits, dot, dash, underscore")
	}
	if strings.TrimSpace(srv.Host) == "" {
		return fmt.Errorf("Host/IP is required")
	}
	if ip := net.ParseIP(srv.Host); ip == nil {
		if strings.Contains(srv.Host, " ") {
			return fmt.Errorf("host must not contain spaces")
		}
		if ok, _ := regexp.MatchString(`^[A-Za-z0-9.-]+$`, srv.Host); !ok {
			return fmt.Errorf("host contains invalid characters")
		}
		if strings.HasPrefix(srv.Host, ".") || strings.HasSuffix(srv.Host, ".") {
			return fmt.Errorf("host must not start or end with a dot")
		}
		for _, lbl := range strings.Split(srv.Host, ".") {
			if lbl == "" {
				return fmt.Errorf("host must not contain empty labels")
			}
			if strings.HasPrefix(lbl, "-") || strings.HasSuffix(lbl, "-") {
				return fmt.Errorf("hostname labels must not start or end with a hyphen")
			}
		}
	}
	if srv.Port != 0 && (srv.Port < 1 || srv.Port > 65535) {
		return fmt.Errorf("port must be a number between 1 and 65535")
	}
	return nil
}

// UpdateServer updates an existing server with new details.
func (s *serverService) UpdateServer(server domain.Server, newServer domain.Server) error {
	if err := validateServer(newServer); err != nil {
		s.logger.Warnw("validation failed on update", "error", err, "server", newServer)
		return err
	}
	err := s.serverRepository.UpdateServer(server, newServer)
	if err != nil {
		s.logger.Errorw("failed to update server", "error", err, "server", server)
	}
	return err
}

// AddServer adds a new server to the repository.
func (s *serverService) AddServer(server domain.Server, targetFile string) error {
	if err := validateServer(server); err != nil {
		s.logger.Warnw("validation failed on add", "error", err, "server", server)
		return err
	}
	err := s.serverRepository.AddServer(server, targetFile)
	if err != nil {
		s.logger.Errorw("failed to add server", "error", err, "server", server)
	}
	return err
}

// DeleteServer removes a server from the repository.
func (s *serverService) DeleteServer(server domain.Server) error {
	err := s.serverRepository.DeleteServer(server)
	if err != nil {
		s.logger.Errorw("failed to delete server", "error", err, "server", server)
	}
	return err
}

// SetPinned sets or clears a pin timestamp for the server alias.
func (s *serverService) SetPinned(alias string, pinned bool) error {
	err := s.serverRepository.SetPinned(alias, pinned)
	if err != nil {
		s.logger.Errorw("failed to set pin state", "error", err, "alias", alias, "pinned", pinned)
	}
	return err
}

// SSH starts an interactive SSH session to the given alias using the system's ssh client.
func (s *serverService) SSH(alias string) error {
	s.logger.Infow("ssh start", "alias", alias)
	cmd := exec.Command("ssh", alias)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		s.logger.Errorw("ssh command failed", "alias", alias, "error", err)
		return err
	}

	if err := s.serverRepository.RecordSSH(alias); err != nil {
		s.logger.Errorw("failed to record ssh metadata", "alias", alias, "error", err)
	}

	s.logger.Infow("ssh end", "alias", alias)
	return nil
}

// SSHWithArgs runs system ssh with provided extra args (e.g., -L/-R/-D) for the given alias.
func (s *serverService) SSHWithArgs(alias string, extraArgs []string) error {
	s.logger.Infow("ssh start (with args)", "alias", alias, "args", extraArgs)
	args := append([]string{}, extraArgs...)
	args = append(args, alias)
	// #nosec G204
	cmd := exec.Command("ssh", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		s.logger.Errorw("ssh (with args) failed", "alias", alias, "error", err)
		return err
	}
	if err := s.serverRepository.RecordSSH(alias); err != nil {
		s.logger.Errorw("failed to record ssh metadata", "alias", alias, "error", err)
	}
	s.logger.Infow("ssh end (with args)", "alias", alias)
	return nil
}

// StartForward starts ssh port forwarding in the background and tracks the process.
func (s *serverService) StartForward(alias string, extraArgs []string) (int, error) {
	s.fwMu.Lock()
	if s.forwards == nil {
		s.forwards = make(map[string][]*os.Process)
	}
	s.fwMu.Unlock()

	extraArgs = append(extraArgs, "-N", alias)

	// #nosec G204
	cmd := exec.Command("ssh", extraArgs...)

	// Detach from TTY: discard stdio
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to open devnull: %w", err)
	}
	defer func() {
		if devNull != nil {
			_ = devNull.Close()
		}
	}()

	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	// Set SysProcAttr in an OS-specific way (see sysprocattr_* files)
	sysProcAttr := &syscall.SysProcAttr{}
	setDetach(sysProcAttr)
	cmd.SysProcAttr = sysProcAttr

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("failed to start ssh: %w", err)
	}

	proc := cmd.Process
	if proc == nil {
		return 0, fmt.Errorf("process is nil after start")
	}
	pid := proc.Pid

	// Track process
	s.fwMu.Lock()
	s.forwards[alias] = append(s.forwards[alias], proc)
	s.fwMu.Unlock()

	// Cleanup on exit
	go func(a string, c *exec.Cmd, dn *os.File) {
		_ = c.Wait()
		_ = dn.Close()

		s.fwMu.Lock()
		defer s.fwMu.Unlock()

		procs := s.forwards[a]
		if len(procs) == 0 {
			return
		}

		filtered := make([]*os.Process, 0, len(procs))
		for _, p := range procs {
			if p != nil && p.Pid != pid {
				filtered = append(filtered, p)
			}
		}

		if len(filtered) == 0 {
			delete(s.forwards, a)
		} else {
			s.forwards[a] = filtered
		}
	}(alias, cmd, devNull)

	devNull = nil // Prevent defer from closing it

	return pid, nil
}

// StopForwarding kills all active forward processes for the alias.
func (s *serverService) StopForwarding(alias string) error {
	s.fwMu.Lock()
	procs := s.forwards[alias]
	delete(s.forwards, alias)
	s.fwMu.Unlock()

	if len(procs) == 0 {
		return nil
	}

	var errs []error
	for _, p := range procs {
		if p != nil {
			if err := p.Signal(syscall.SIGTERM); err != nil {
				// If SIGTERM fails, try SIGKILL
				if killErr := p.Kill(); killErr != nil {
					errs = append(errs, fmt.Errorf("failed to kill pid %d: %w", p.Pid, killErr))
				}
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors stopping forwards: %v", errs)
	}
	return nil
}

// IsForwarding reports whether there is at least one active forward for alias.
func (s *serverService) IsForwarding(alias string) bool {
	s.fwMu.Lock()
	defer s.fwMu.Unlock()
	return len(s.forwards[alias]) > 0
}

// Ping checks if the server is reachable on its SSH port.
func (s *serverService) Ping(server domain.Server) (bool, time.Duration, error) {
	start := time.Now()

	host, port, ok := resolveSSHDestination(server.Alias)
	if !ok {

		host = strings.TrimSpace(server.Host)
		if host == "" {
			host = server.Alias
		}
		if server.Port > 0 {
			port = server.Port
		} else {
			port = 22
		}
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return false, time.Since(start), err
	}
	_ = conn.Close()
	return true, time.Since(start), nil
}

// resolveSSHDestination uses `ssh -G <alias>` to extract HostName and Port from the user's SSH config.
// Returns host, port, ok where ok=false if resolution failed.
func resolveSSHDestination(alias string) (string, int, bool) {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return "", 0, false
	}
	cmd := exec.Command("ssh", "-G", alias)
	out, err := cmd.Output()
	if err != nil {
		return "", 0, false
	}
	host := ""
	port := 0
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "hostname ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				host = parts[1]
			}
		}
		if strings.HasPrefix(line, "port ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if p, err := strconv.Atoi(parts[1]); err == nil {
					port = p
				}
			}
		}
	}
	if host == "" {
		host = alias
	}
	if port == 0 {
		port = 22
	}
	return host, port, true
}

func (s *serverService) resolveIPLocationCache(server domain.Server, now time.Time) (domain.IPLocationCache, bool, error) {
	host := strings.TrimSpace(server.Host)
	if host == "" {
		host = strings.TrimSpace(server.Alias)
	}
	if host == "" {
		return domain.IPLocationCache{}, false, nil
	}

	resolvedIP, isPrivate, err := s.resolveTargetIP(host)
	if err != nil {
		return domain.IPLocationCache{}, false, fmt.Errorf("resolve host %q ip: %w", host, err)
	}

	if !shouldRefreshIPLocation(server, resolvedIP, now) {
		return domain.IPLocationCache{}, false, nil
	}

	if isPrivate {
		return domain.IPLocationCache{
			ResolvedIP:          resolvedIP,
			IPLocationShort:     "LAN",
			IPLocationUpdatedAt: now,
		}, true, nil
	}

	location, err := s.fetchIPLocationShort(resolvedIP)
	if err != nil {
		return domain.IPLocationCache{}, false, fmt.Errorf("fetch geo location for %s: %w", resolvedIP, err)
	}

	return domain.IPLocationCache{
		ResolvedIP:          resolvedIP,
		IPLocationShort:     location,
		IPLocationUpdatedAt: now,
	}, true, nil
}

func shouldRefreshIPLocation(server domain.Server, resolvedIP string, now time.Time) bool {
	if strings.TrimSpace(resolvedIP) == "" {
		return false
	}
	if strings.TrimSpace(server.ResolvedIP) != strings.TrimSpace(resolvedIP) {
		return true
	}
	if strings.TrimSpace(server.IPLocationShort) == "" {
		return true
	}
	if server.IPLocationUpdatedAt.IsZero() {
		return true
	}
	return now.Sub(server.IPLocationUpdatedAt) >= geoIPCacheTTL
}

func (s *serverService) resolveTargetIP(host string) (string, bool, error) {
	if parsed := net.ParseIP(host); parsed != nil {
		normalized := normalizeIP(parsed)
		return normalized, isPrivateOrLocalIP(parsed), nil
	}

	ips, err := s.lookupIP(host)
	if err != nil {
		return "", false, err
	}
	if len(ips) == 0 {
		return "", false, fmt.Errorf("no ip resolved for host %q", host)
	}

	var privateFallback string
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		normalized := normalizeIP(ip)
		if normalized == "" {
			continue
		}
		if isPrivateOrLocalIP(ip) {
			if privateFallback == "" {
				privateFallback = normalized
			}
			continue
		}
		return normalized, false, nil
	}

	if privateFallback != "" {
		return privateFallback, true, nil
	}

	return "", false, fmt.Errorf("no usable ip resolved for host %q", host)
}

func normalizeIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func isPrivateOrLocalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}
	return ip.IsPrivate()
}

func (s *serverService) fetchIPLocationShort(ip string) (string, error) {
	clients := make([]*http.Client, 0, 2)
	if s.httpClient != nil {
		clients = append(clients, s.httpClient)
	}
	if s.directHTTPClient != nil {
		clients = append(clients, s.directHTTPClient)
	}
	if len(clients) == 0 {
		clients = append(clients, &http.Client{Timeout: geoIPRequestTimeout})
	}

	var errs []error
	for _, client := range clients {
		location, err := s.fetchFromIPAPI(client, ip)
		if err == nil {
			return location, nil
		}
		errs = append(errs, err)
	}

	for _, client := range clients {
		location, err := s.fetchFromIPWhois(client, ip)
		if err == nil {
			return location, nil
		}
		errs = append(errs, err)
	}

	return "", fmt.Errorf("geo lookup failed: %v", errs)
}

func (s *serverService) fetchFromIPAPI(client *http.Client, ip string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(s.geoIPBaseURL), "/")
	if base == "" {
		base = defaultGeoIPBaseURL
	}

	endpoint := fmt.Sprintf("%s/%s", base, neturl.PathEscape(ip))
	ctx, cancel := context.WithTimeout(context.Background(), geoIPRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return "", fmt.Errorf("geoip status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		Region      string `json:"region"`
		RegionName  string `json:"regionregionName"`
		Query       string `json:"query"`
		Message     string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if strings.ToLower(payload.Status) != "success" {
		if payload.Message == "" {
			payload.Message = "unknown geoip error"
		}
		return "", errors.New(payload.Message)
	}

	country := strings.ToUpper(strings.TrimSpace(payload.Country))
	region := strings.ToUpper(strings.TrimSpace(payload.RegionName))
	if country == "" {
		return "", fmt.Errorf("geoip response missing country code for %s", ip)
	}
	if region == "" {
		region = "--"
	}

	return country + "/" + region, nil
}

func (s *serverService) fetchFromIPWhois(client *http.Client, ip string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(s.geoIPWhoisBaseURL), "/")
	if base == "" {
		base = defaultGeoIPWhois
	}
	endpoint := fmt.Sprintf("%s/%s", base, neturl.PathEscape(ip))
	ctx, cancel := context.WithTimeout(context.Background(), geoIPRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return "", fmt.Errorf("ipwhois status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Success     bool   `json:"success"`
		CountryCode string `json:"country_code"`
		RegionCode  string `json:"region_code"`
		Error       struct {
			Message string `json:"message"`
		} `json:"error"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if !payload.Success {
		msg := strings.TrimSpace(payload.Error.Message)
		if msg == "" {
			msg = strings.TrimSpace(payload.Message)
		}
		if msg == "" {
			msg = "unknown ipwhois error"
		}
		return "", errors.New(msg)
	}

	country := strings.ToUpper(strings.TrimSpace(payload.CountryCode))
	region := strings.ToUpper(strings.TrimSpace(payload.RegionCode))
	if country == "" {
		return "", fmt.Errorf("ipwhois response missing country code for %s", ip)
	}
	if region == "" {
		region = "--"
	}
	return country + "/" + region, nil
}
