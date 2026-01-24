package opnsensednsmasq

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestTrimZone(t *testing.T) {
	tests := []struct {
		name     string
		zone     string
		expected string
	}{
		{"with trailing dot", "example.com.", "example.com"},
		{"without trailing dot", "example.com", "example.com"},
		{"empty string", "", ""},
		{"only dot", ".", ""},
		{"multiple dots", "sub.example.com.", "sub.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := trimZone(tt.zone)
			if result != tt.expected {
				t.Errorf("trimZone(%q) = %q, want %q", tt.zone, result, tt.expected)
			}
		})
	}
}

func TestResolveHostAndDomain(t *testing.T) {
	tests := []struct {
		name           string
		recordName     string
		zone           string
		expectedHost   string
		expectedDomain string
	}{
		{"normal subdomain", "www", "example.com", "www", "example.com"},
		{"zone apex with @", "@", "example.com", "example", "com"},
		{"zone apex empty", "", "example.com", "example", "com"},
		{"subdomain with trailing dot zone", "api", "example.com.", "api", "example.com"},
		{"apex with trailing dot zone", "@", "my_domain.org.", "my_domain", "org"},
		{"single label zone apex", "@", "localhost", "localhost", ""},
		{"deep subdomain", "deep.sub", "example.com", "deep.sub", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, domain := resolveHostAndDomain(tt.recordName, tt.zone)
			if host != tt.expectedHost || domain != tt.expectedDomain {
				t.Errorf("resolveHostAndDomain(%q, %q) = (%q, %q), want (%q, %q)",
					tt.recordName, tt.zone, host, domain, tt.expectedHost, tt.expectedDomain)
			}
		})
	}
}

func TestGetDescription(t *testing.T) {
	tests := []struct {
		name        string
		description string
		expected    string
	}{
		{"custom description", "My Custom Desc", "My Custom Desc"},
		{"empty description", "", "Managed by Caddy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{Description: tt.description}
			result := p.getDescription()
			if result != tt.expected {
				t.Errorf("getDescription() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestBaseURL(t *testing.T) {
	p := &Provider{Host: "opnsense.local"}
	expected := "https://opnsense.local/api/dnsmasq"
	result := p.baseURL()
	if result != expected {
		t.Errorf("baseURL() = %q, want %q", result, expected)
	}
}

func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(handler)
}

func newTestProvider(t *testing.T, serverURL string) *Provider {
	t.Helper()
	// Extract host from URL (remove https://)
	host := strings.TrimPrefix(serverURL, "https://")
	p := &Provider{
		Host:      host,
		APIKey:    "test-key",
		APISecret: "test-secret",
		Insecure:  true,
	}
	return p
}

func TestGetRecords(t *testing.T) {
	tests := []struct {
		name           string
		zone           string
		serverResponse searchHostResponse
		expectedCount  int
		expectedNames  []string
	}{
		{
			name: "returns matching records",
			zone: "example.com",
			serverResponse: searchHostResponse{
				Rows: []dnsmasqHost{
					{UUID: "1", Host: "www", Domain: "example.com", IP: "192.168.1.1"},
					{UUID: "2", Host: "api", Domain: "example.com", IP: "192.168.1.2"},
					{UUID: "3", Host: "other", Domain: "otherdomain.com", IP: "192.168.1.3"},
				},
			},
			expectedCount: 2,
			expectedNames: []string{"www", "api"},
		},
		{
			name: "returns apex record",
			zone: "my_domain.com",
			serverResponse: searchHostResponse{
				Rows: []dnsmasqHost{
					{UUID: "1", Host: "my_domain", Domain: "com", IP: "192.168.1.1"},
				},
			},
			expectedCount: 1,
			expectedNames: []string{"@"},
		},
		{
			name: "returns IPv6 records",
			zone: "example.com",
			serverResponse: searchHostResponse{
				Rows: []dnsmasqHost{
					{UUID: "1", Host: "www", Domain: "example.com", IP: "2001:db8::1"},
				},
			},
			expectedCount: 1,
			expectedNames: []string{"www"},
		},
		{
			name: "empty response",
			zone: "example.com",
			serverResponse: searchHostResponse{
				Rows: []dnsmasqHost{},
			},
			expectedCount: 0,
			expectedNames: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/dnsmasq/settings/search_host" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				if r.Method != http.MethodGet {
					t.Errorf("unexpected method: %s", r.Method)
				}

				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.serverResponse)
			})
			defer server.Close()

			p := newTestProvider(t, server.URL)
			records, err := p.GetRecords(context.Background(), tt.zone)
			if err != nil {
				t.Fatalf("GetRecords() error = %v", err)
			}

			if len(records) != tt.expectedCount {
				t.Errorf("GetRecords() returned %d records, want %d", len(records), tt.expectedCount)
			}

			for i, expectedName := range tt.expectedNames {
				if i >= len(records) {
					break
				}
				rr := records[i].RR()
				if rr.Name != expectedName {
					t.Errorf("record[%d].Name = %q, want %q", i, rr.Name, expectedName)
				}
			}
		})
	}
}

func TestAppendRecords(t *testing.T) {
	tests := []struct {
		name          string
		zone          string
		records       []libdns.Record
		expectError   bool
		expectedAdded int
	}{
		{
			name: "append A record",
			zone: "example.com",
			records: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.1")},
			},
			expectError:   false,
			expectedAdded: 1,
		},
		{
			name: "append AAAA record",
			zone: "example.com",
			records: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("2001:db8::1")},
			},
			expectError:   false,
			expectedAdded: 1,
		},
		{
			name: "append multiple records",
			zone: "example.com",
			records: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.1")},
				libdns.Address{Name: "api", IP: mustParseAddr("192.168.1.2")},
			},
			expectError:   false,
			expectedAdded: 2,
		},
		{
			name: "reject unsupported record type",
			zone: "example.com",
			records: []libdns.Record{
				libdns.TXT{Name: "txt", Text: "some text"},
			},
			expectError:   true,
			expectedAdded: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addCount := 0
			reconfigured := false

			server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")

				if strings.HasPrefix(r.URL.Path, "/api/dnsmasq/settings/add_host") {
					addCount++
					_ = json.NewEncoder(w).Encode(apiResponse{Result: "saved"})
					return
				}
				if r.URL.Path == "/api/dnsmasq/service/reconfigure" {
					reconfigured = true
					_ = json.NewEncoder(w).Encode(apiResponse{Status: "ok"})
					return
				}
				t.Errorf("unexpected path: %s", r.URL.Path)
			})
			defer server.Close()

			p := newTestProvider(t, server.URL)
			added, err := p.AppendRecords(context.Background(), tt.zone, tt.records)

			if tt.expectError {
				if err == nil {
					t.Error("AppendRecords() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("AppendRecords() error = %v", err)
			}

			if len(added) != tt.expectedAdded {
				t.Errorf("AppendRecords() added %d records, want %d", len(added), tt.expectedAdded)
			}

			if addCount != tt.expectedAdded {
				t.Errorf("add_host called %d times, want %d", addCount, tt.expectedAdded)
			}

			if tt.expectedAdded > 0 && !reconfigured {
				t.Error("reconfigure was not called")
			}
		})
	}
}

func TestDeleteRecords(t *testing.T) {
	tests := []struct {
		name            string
		zone            string
		existingHosts   []dnsmasqHost
		recordsToDelete []libdns.Record
		expectedDeleted int
	}{
		{
			name: "delete existing record",
			zone: "example.com",
			existingHosts: []dnsmasqHost{
				{UUID: "uuid-1", Host: "www", Domain: "example.com", IP: "192.168.1.1"},
			},
			recordsToDelete: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.1")},
			},
			expectedDeleted: 1,
		},
		{
			name: "delete non-existing record",
			zone: "example.com",
			existingHosts: []dnsmasqHost{
				{UUID: "uuid-1", Host: "www", Domain: "example.com", IP: "192.168.1.1"},
			},
			recordsToDelete: []libdns.Record{
				libdns.Address{Name: "api", IP: mustParseAddr("192.168.1.2")},
			},
			expectedDeleted: 0,
		},
		{
			name: "delete apex record",
			zone: "my_domain.com",
			existingHosts: []dnsmasqHost{
				{UUID: "uuid-1", Host: "my_domain", Domain: "com", IP: "192.168.1.1"},
			},
			recordsToDelete: []libdns.Record{
				libdns.Address{Name: "@", IP: mustParseAddr("192.168.1.1")},
			},
			expectedDeleted: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deleteCount := 0
			reconfigured := false

			server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")

				if r.URL.Path == "/api/dnsmasq/settings/search_host" {
					_ = json.NewEncoder(w).Encode(searchHostResponse{Rows: tt.existingHosts})
					return
				}
				if strings.HasPrefix(r.URL.Path, "/api/dnsmasq/settings/del_host/") {
					deleteCount++
					_ = json.NewEncoder(w).Encode(apiResponse{Result: "deleted"})
					return
				}
				if r.URL.Path == "/api/dnsmasq/service/reconfigure" {
					reconfigured = true
					_ = json.NewEncoder(w).Encode(apiResponse{Status: "ok"})
					return
				}
				t.Errorf("unexpected path: %s", r.URL.Path)
			})
			defer server.Close()

			p := newTestProvider(t, server.URL)
			deleted, err := p.DeleteRecords(context.Background(), tt.zone, tt.recordsToDelete)
			if err != nil {
				t.Fatalf("DeleteRecords() error = %v", err)
			}

			if len(deleted) != tt.expectedDeleted {
				t.Errorf("DeleteRecords() deleted %d records, want %d", len(deleted), tt.expectedDeleted)
			}

			if deleteCount != tt.expectedDeleted {
				t.Errorf("del_host called %d times, want %d", deleteCount, tt.expectedDeleted)
			}

			if tt.expectedDeleted > 0 && !reconfigured {
				t.Error("reconfigure was not called")
			}
		})
	}
}

func TestSetRecords(t *testing.T) {
	tests := []struct {
		name          string
		zone          string
		existingHosts []dnsmasqHost
		recordsToSet  []libdns.Record
		expectAdd     int
		expectDelete  int
	}{
		{
			name:          "create new record",
			zone:          "example.com",
			existingHosts: []dnsmasqHost{},
			recordsToSet: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.1")},
			},
			expectAdd:    1,
			expectDelete: 0,
		},
		{
			name: "update existing record",
			zone: "example.com",
			existingHosts: []dnsmasqHost{
				{UUID: "uuid-1", Host: "www", Domain: "example.com", IP: "192.168.1.1", Descr: "Managed by Caddy"},
			},
			recordsToSet: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.2")},
			},
			expectAdd:    1,
			expectDelete: 1,
		},
		{
			name: "skip identical record",
			zone: "example.com",
			existingHosts: []dnsmasqHost{
				{UUID: "uuid-1", Host: "www", Domain: "example.com", IP: "192.168.1.1", Descr: "Managed by Caddy"},
			},
			recordsToSet: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.1")},
			},
			expectAdd:    0,
			expectDelete: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addCount := 0
			deleteCount := 0
			reconfigured := false

			server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")

				if r.URL.Path == "/api/dnsmasq/settings/search_host" {
					_ = json.NewEncoder(w).Encode(searchHostResponse{Rows: tt.existingHosts})
					return
				}
				if strings.HasPrefix(r.URL.Path, "/api/dnsmasq/settings/add_host") {
					addCount++
					_ = json.NewEncoder(w).Encode(apiResponse{Result: "saved"})
					return
				}
				if strings.HasPrefix(r.URL.Path, "/api/dnsmasq/settings/del_host/") {
					deleteCount++
					_ = json.NewEncoder(w).Encode(apiResponse{Result: "deleted"})
					return
				}
				if r.URL.Path == "/api/dnsmasq/service/reconfigure" {
					reconfigured = true
					_ = json.NewEncoder(w).Encode(apiResponse{Status: "ok"})
					return
				}
				t.Errorf("unexpected path: %s", r.URL.Path)
			})
			defer server.Close()

			p := newTestProvider(t, server.URL)
			_, err := p.SetRecords(context.Background(), tt.zone, tt.recordsToSet)
			if err != nil {
				t.Fatalf("SetRecords() error = %v", err)
			}

			if addCount != tt.expectAdd {
				t.Errorf("add_host called %d times, want %d", addCount, tt.expectAdd)
			}

			if deleteCount != tt.expectDelete {
				t.Errorf("del_host called %d times, want %d", deleteCount, tt.expectDelete)
			}

			needsReconfigure := tt.expectAdd > 0 || tt.expectDelete > 0
			if needsReconfigure && !reconfigured {
				t.Error("reconfigure was not called")
			}
			if !needsReconfigure && reconfigured {
				t.Error("reconfigure was called unexpectedly")
			}
		})
	}
}

func TestAPIErrorHandling(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
	}{
		{"server error", http.StatusInternalServerError, "Internal Server Error"},
		{"unauthorized", http.StatusUnauthorized, "Unauthorized"},
		{"not found", http.StatusNotFound, "Not Found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.response))
			})
			defer server.Close()

			p := newTestProvider(t, server.URL)
			_, err := p.GetRecords(context.Background(), "example.com")

			if err == nil {
				t.Error("expected error, got nil")
			}

			if !strings.Contains(err.Error(), "API error") {
				t.Errorf("error should contain 'API error', got: %v", err)
			}
		})
	}
}

func TestGetCleanupDelay(t *testing.T) {
	tests := []struct {
		name     string
		delay    time.Duration
		expected time.Duration
	}{
		{"custom delay", 10 * time.Second, 10 * time.Second},
		{"zero delay uses default", 0, DefaultCleanupDelay},
		{"negative delay uses default", -1 * time.Second, DefaultCleanupDelay},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{CleanupDelay: tt.delay}
			result := p.getCleanupDelay()
			if result != tt.expected {
				t.Errorf("getCleanupDelay() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestTrackManagedRecord(t *testing.T) {
	p := &Provider{}

	// Track first record
	p.trackManagedRecord("www", "example.com")

	if len(p.managedRecords) != 1 {
		t.Errorf("managedRecords has %d entries, want 1", len(p.managedRecords))
	}
	if _, ok := p.managedRecords["www:example.com"]; !ok {
		t.Error("managedRecords missing 'www:example.com'")
	}
	if _, ok := p.syncZones["example.com"]; !ok {
		t.Error("syncZones missing 'example.com'")
	}

	// Track second record in same zone
	p.trackManagedRecord("api", "example.com")

	if len(p.managedRecords) != 2 {
		t.Errorf("managedRecords has %d entries, want 2", len(p.managedRecords))
	}
	if len(p.syncZones) != 1 {
		t.Errorf("syncZones has %d entries, want 1", len(p.syncZones))
	}

	// Track record in different zone
	p.trackManagedRecord("mail", "other.com")

	if len(p.managedRecords) != 3 {
		t.Errorf("managedRecords has %d entries, want 3", len(p.managedRecords))
	}
	if len(p.syncZones) != 2 {
		t.Errorf("syncZones has %d entries, want 2", len(p.syncZones))
	}
}

func TestCleanupOrphanedRecords(t *testing.T) {
	tests := []struct {
		name           string
		existingHosts  []dnsmasqHost
		managedRecords map[string]struct{}
		syncZones      map[string]struct{}
		expectDeleted  int
	}{
		{
			name: "cleanup orphaned record",
			existingHosts: []dnsmasqHost{
				{UUID: "1", Host: "www", Domain: "example.com", IP: "192.168.1.1", Descr: "Managed by Caddy"},
				{UUID: "2", Host: "api", Domain: "example.com", IP: "192.168.1.2", Descr: "Managed by Caddy"},
				{UUID: "3", Host: "orphan", Domain: "example.com", IP: "192.168.1.3", Descr: "Managed by Caddy"},
			},
			managedRecords: map[string]struct{}{
				"www:example.com": {},
				"api:example.com": {},
			},
			syncZones:     map[string]struct{}{"example.com": {}},
			expectDeleted: 1,
		},
		{
			name: "skip records with different description",
			existingHosts: []dnsmasqHost{
				{UUID: "1", Host: "www", Domain: "example.com", IP: "192.168.1.1", Descr: "Managed by Caddy"},
				{UUID: "2", Host: "manual", Domain: "example.com", IP: "192.168.1.2", Descr: "Manual Entry"},
			},
			managedRecords: map[string]struct{}{
				"www:example.com": {},
			},
			syncZones:     map[string]struct{}{"example.com": {}},
			expectDeleted: 0,
		},
		{
			name: "skip records in untouched zones",
			existingHosts: []dnsmasqHost{
				{UUID: "1", Host: "www", Domain: "example.com", IP: "192.168.1.1", Descr: "Managed by Caddy"},
				{UUID: "2", Host: "other", Domain: "other.com", IP: "192.168.1.2", Descr: "Managed by Caddy"},
			},
			managedRecords: map[string]struct{}{
				"www:example.com": {},
			},
			syncZones:     map[string]struct{}{"example.com": {}},
			expectDeleted: 0,
		},
		{
			name: "no cleanup when no zones touched",
			existingHosts: []dnsmasqHost{
				{UUID: "1", Host: "orphan", Domain: "example.com", IP: "192.168.1.1", Descr: "Managed by Caddy"},
			},
			managedRecords: map[string]struct{}{},
			syncZones:      map[string]struct{}{},
			expectDeleted:  0,
		},
		{
			name: "cleanup multiple orphans",
			existingHosts: []dnsmasqHost{
				{UUID: "1", Host: "www", Domain: "example.com", IP: "192.168.1.1", Descr: "Managed by Caddy"},
				{UUID: "2", Host: "orphan1", Domain: "example.com", IP: "192.168.1.2", Descr: "Managed by Caddy"},
				{UUID: "3", Host: "orphan2", Domain: "example.com", IP: "192.168.1.3", Descr: "Managed by Caddy"},
			},
			managedRecords: map[string]struct{}{
				"www:example.com": {},
			},
			syncZones:     map[string]struct{}{"example.com": {}},
			expectDeleted: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deleteCount := 0
			reconfigured := false

			server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")

				if r.URL.Path == "/api/dnsmasq/settings/search_host" {
					_ = json.NewEncoder(w).Encode(searchHostResponse{Rows: tt.existingHosts})
					return
				}
				if strings.HasPrefix(r.URL.Path, "/api/dnsmasq/settings/del_host/") {
					deleteCount++
					_ = json.NewEncoder(w).Encode(apiResponse{Result: "deleted"})
					return
				}
				if r.URL.Path == "/api/dnsmasq/service/reconfigure" {
					reconfigured = true
					_ = json.NewEncoder(w).Encode(apiResponse{Status: "ok"})
					return
				}
				t.Errorf("unexpected path: %s", r.URL.Path)
			})
			defer server.Close()

			p := newTestProvider(t, server.URL)
			p.managedRecords = tt.managedRecords
			p.syncZones = tt.syncZones

			p.cleanupOrphanedRecords(context.Background())

			if deleteCount != tt.expectDeleted {
				t.Errorf("deleted %d records, want %d", deleteCount, tt.expectDeleted)
			}

			if tt.expectDeleted > 0 && !reconfigured {
				t.Error("reconfigure was not called")
			}
			if tt.expectDeleted == 0 && reconfigured {
				t.Error("reconfigure was called unexpectedly")
			}

			// Verify tracking was reset
			if len(p.managedRecords) != 0 {
				t.Errorf("managedRecords not reset, has %d entries", len(p.managedRecords))
			}
			if len(p.syncZones) != 0 {
				t.Errorf("syncZones not reset, has %d entries", len(p.syncZones))
			}
		})
	}
}

func TestSetRecordsTracksRecords(t *testing.T) {
	server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/dnsmasq/settings/search_host" {
			_ = json.NewEncoder(w).Encode(searchHostResponse{Rows: []dnsmasqHost{}})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/dnsmasq/settings/add_host") {
			_ = json.NewEncoder(w).Encode(apiResponse{Result: "saved"})
			return
		}
		if r.URL.Path == "/api/dnsmasq/service/reconfigure" {
			_ = json.NewEncoder(w).Encode(apiResponse{Status: "ok"})
			return
		}
	})
	defer server.Close()

	p := newTestProvider(t, server.URL)
	p.CleanupDelay = 1 * time.Hour // Long delay so timer doesn't fire during test

	records := []libdns.Record{
		libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.1")},
		libdns.Address{Name: "api", IP: mustParseAddr("192.168.1.2")},
	}

	_, err := p.SetRecords(context.Background(), "example.com", records)
	if err != nil {
		t.Fatalf("SetRecords() error = %v", err)
	}

	// Verify records were tracked
	if len(p.managedRecords) != 2 {
		t.Errorf("managedRecords has %d entries, want 2", len(p.managedRecords))
	}
	if _, ok := p.managedRecords["www:example.com"]; !ok {
		t.Error("managedRecords missing 'www:example.com'")
	}
	if _, ok := p.managedRecords["api:example.com"]; !ok {
		t.Error("managedRecords missing 'api:example.com'")
	}
	if _, ok := p.syncZones["example.com"]; !ok {
		t.Error("syncZones missing 'example.com'")
	}

	// Stop timer to clean up
	p.syncMu.Lock()
	if p.syncTimer != nil {
		p.syncTimer.Stop()
	}
	p.syncMu.Unlock()
}

// Helper function for tests
func mustParseAddr(s string) (addr netip.Addr) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr
}
