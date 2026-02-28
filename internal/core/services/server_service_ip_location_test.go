package services

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Adembc/lazyssh/internal/core/domain"
	"go.uber.org/zap"
)

type ipLocationRepoStub struct {
	updated map[string]domain.IPLocationCache
}

func (r *ipLocationRepoStub) ListServers(query string) ([]domain.Server, error) { return nil, nil }
func (r *ipLocationRepoStub) ListConfigFiles() ([]string, error)                { return nil, nil }
func (r *ipLocationRepoStub) UpdateServer(server domain.Server, newServer domain.Server) error {
	return nil
}
func (r *ipLocationRepoStub) AddServer(server domain.Server, targetFile string) error { return nil }
func (r *ipLocationRepoStub) DeleteServer(server domain.Server) error                 { return nil }
func (r *ipLocationRepoStub) SetPinned(alias string, pinned bool) error               { return nil }
func (r *ipLocationRepoStub) RecordSSH(alias string) error                            { return nil }
func (r *ipLocationRepoStub) UpdateIPLocationMetadata(updates map[string]domain.IPLocationCache) error {
	if r.updated == nil {
		r.updated = make(map[string]domain.IPLocationCache)
	}
	for k, v := range updates {
		r.updated[k] = v
	}
	return nil
}

func TestEnrichIPLocation_FetchAndPersist(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"success","countryCode":"US","region":"CA","query":"8.8.8.8"}`)
	}))
	defer ts.Close()

	repo := &ipLocationRepoStub{}
	svc := &serverService{
		serverRepository: repo,
		logger:           zap.NewNop().Sugar(),
		httpClient:       &http.Client{Timeout: time.Second},
		geoIPBaseURL:     ts.URL + "/",
		now:              func() time.Time { return time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC) },
	}

	servers := []domain.Server{{Alias: "dns", Host: "8.8.8.8"}}
	enriched, err := svc.EnrichIPLocation(servers)
	if err != nil {
		t.Fatalf("EnrichIPLocation returned error: %v", err)
	}

	if got := enriched[0].IPLocationShort; got != "US/CA" {
		t.Fatalf("expected IPLocationShort US/CA, got %q", got)
	}
	if got := enriched[0].ResolvedIP; got != "8.8.8.8" {
		t.Fatalf("expected ResolvedIP 8.8.8.8, got %q", got)
	}

	persisted, ok := repo.updated["dns"]
	if !ok {
		t.Fatalf("expected metadata update for alias dns")
	}
	if persisted.IPLocationShort != "US/CA" {
		t.Fatalf("expected persisted location US/CA, got %q", persisted.IPLocationShort)
	}
}

func TestEnrichIPLocation_PrivateAddressUsesLAN(t *testing.T) {
	repo := &ipLocationRepoStub{}
	svc := &serverService{
		serverRepository: repo,
		logger:           zap.NewNop().Sugar(),
		httpClient:       &http.Client{Timeout: time.Second},
		geoIPBaseURL:     "http://127.0.0.1.invalid/",
		now:              func() time.Time { return time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC) },
	}

	servers := []domain.Server{{Alias: "lan", Host: "192.168.1.20"}}
	enriched, err := svc.EnrichIPLocation(servers)
	if err != nil {
		t.Fatalf("EnrichIPLocation returned error: %v", err)
	}
	if got := enriched[0].IPLocationShort; got != "LAN" {
		t.Fatalf("expected LAN location, got %q", got)
	}
	if got := enriched[0].ResolvedIP; got != "192.168.1.20" {
		t.Fatalf("expected resolved private IP, got %q", got)
	}
}

type alwaysFailRoundTripper struct{}

func (alwaysFailRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("forced transport failure")
}

func TestFetchIPLocationShort_FallbackToDirectClientAndHTTPSProvider(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/json/8.8.8.8" {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprint(w, `{"status":"fail","message":"bad gateway"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"success":true,"country_code":"US","region_code":"CA"}`)
	}))
	defer ts.Close()

	svc := &serverService{
		logger:            zap.NewNop().Sugar(),
		httpClient:        &http.Client{Transport: alwaysFailRoundTripper{}, Timeout: time.Second},
		directHTTPClient:  &http.Client{Timeout: time.Second},
		geoIPBaseURL:      ts.URL + "/json",
		geoIPWhoisBaseURL: ts.URL,
	}

	got, err := svc.fetchIPLocationShort("8.8.8.8")
	if err != nil {
		t.Fatalf("fetchIPLocationShort returned error: %v", err)
	}
	if got != "US/CA" {
		t.Fatalf("expected location US/CA, got %q", got)
	}
}
