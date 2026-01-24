// Package opnsensednsmasq implements a DNS record management client compatible
// with the libdns interfaces for OPNsense Dnsmasq host overrides.
//
// This provider manages local DNS host entries via the OPNsense API.
// Only A and AAAA records are supported (no TXT records, so ACME DNS challenges
// cannot be performed with this provider).
package opnsensednsmasq

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

// DefaultCleanupDelay is the default delay before orphan cleanup runs
const DefaultCleanupDelay = 5 * time.Second

// Provider facilitates DNS record manipulation with OPNsense Dnsmasq.
type Provider struct {
	// Host is the OPNsense hostname or IP address (e.g., "opnsense.example.com" or "192.168.1.1")
	Host string `json:"host,omitempty"`
	// APIKey is the OPNsense API key
	APIKey string `json:"api_key,omitempty"`
	// APISecret is the OPNsense API secret
	APISecret string `json:"api_secret,omitempty"`
	// Insecure skips TLS certificate verification (for self-signed certificates)
	Insecure bool `json:"insecure,omitempty"`
	// Description is set on created host entries (defaults to "Managed by Caddy")
	Description string `json:"description,omitempty"`
	// CleanupDelay is the delay after last SetRecords before orphan cleanup runs (default 5s)
	CleanupDelay time.Duration `json:"cleanup_delay,omitempty"`
	// Logger is an optional logger. If set, warnings will be logged using this logger.
	// When used with Caddy, set this to ctx.Logger() during Provision to match Caddy's log format.
	Logger *zap.Logger `json:"-"`

	client     *http.Client
	clientOnce sync.Once

	// Sync tracking for orphan cleanup
	syncMu         sync.Mutex
	syncTimer      *time.Timer
	managedRecords map[string]struct{} // key: "host:domain"
	syncZones      map[string]struct{} // zones touched this session
}

// dnsmasqHost represents a host entry from the OPNsense Dnsmasq API
type dnsmasqHost struct {
	UUID   string `json:"uuid"`
	Host   string `json:"host"`
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Descr  string `json:"descr"`
}

// searchHostResponse is the response from settings/search_host
type searchHostResponse struct {
	Rows []dnsmasqHost `json:"rows"`
}

// addHostRequest is the request body for settings/add_host
type addHostRequest struct {
	Host addHostData `json:"host"`
}

type addHostData struct {
	Host   string `json:"host"`
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Descr  string `json:"descr"`
}

// apiResponse is a generic API response
type apiResponse struct {
	Result  string `json:"result,omitempty"`
	Status  string `json:"status,omitempty"`
	Message string `json:"message,omitempty"`
}

func (p *Provider) getClient() *http.Client {
	p.clientOnce.Do(func() {
		transport := &http.Transport{}
		if p.Insecure {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		p.client = &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}
	})
	return p.client
}

func (p *Provider) getDescription() string {
	if p.Description != "" {
		return p.Description
	}
	return "Managed by Caddy"
}

func (p *Provider) getLogger() *zap.Logger {
	if p.Logger != nil {
		return p.Logger
	}
	return zap.NewNop()
}

func (p *Provider) baseURL() string {
	return fmt.Sprintf("https://%s/api/dnsmasq", p.Host)
}

func (p *Provider) doRequest(ctx context.Context, method, endpoint string, body io.Reader) ([]byte, error) {
	url := p.baseURL() + "/" + endpoint
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.SetBasicAuth(p.APIKey, p.APISecret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.getClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (p *Provider) searchHosts(ctx context.Context) ([]dnsmasqHost, error) {
	respBody, err := p.doRequest(ctx, http.MethodGet, "settings/search_host", nil)
	if err != nil {
		return nil, err
	}

	var result searchHostResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return result.Rows, nil
}

func (p *Provider) addHost(ctx context.Context, host, domain, ip string) error {
	// Determine record type from IP for logging
	addr, _ := netip.ParseAddr(ip)
	rr := "A"
	if addr.Is6() {
		rr = "AAAA"
	}

	p.getLogger().Debug("adding host",
		zap.String("host", host),
		zap.String("domain", domain),
		zap.String("type", rr),
		zap.String("ip", ip))

	reqData := addHostRequest{
		Host: addHostData{
			Host:   host,
			Domain: domain,
			IP:     ip,
			Descr:  p.getDescription(),
		},
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	respBody, err := p.doRequest(ctx, http.MethodPost, "settings/add_host", strings.NewReader(string(reqBody)))
	if err != nil {
		return err
	}

	var result apiResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if result.Result != "saved" {
		return fmt.Errorf("failed to add host: %s", result.Message)
	}

	return nil
}

func (p *Provider) deleteHost(ctx context.Context, uuid string) error {
	p.getLogger().Debug("deleting host", zap.String("uuid", uuid))

	respBody, err := p.doRequest(ctx, http.MethodPost, "settings/del_host/"+uuid, nil)
	if err != nil {
		return err
	}

	var result apiResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if result.Result != "deleted" {
		return fmt.Errorf("failed to delete host: %s", result.Message)
	}

	return nil
}

func (p *Provider) reconfigure(ctx context.Context) error {
	p.getLogger().Debug("reconfiguring dnsmasq service")

	respBody, err := p.doRequest(ctx, http.MethodPost, "service/reconfigure", nil)
	if err != nil {
		return err
	}

	var result apiResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if result.Status != "ok" {
		return fmt.Errorf("failed to reconfigure: %s", result.Message)
	}

	p.getLogger().Info("dnsmasq service reconfigured")
	return nil
}

// getCleanupDelay returns the cleanup delay, defaulting to DefaultCleanupDelay
func (p *Provider) getCleanupDelay() time.Duration {
	if p.CleanupDelay > 0 {
		return p.CleanupDelay
	}
	return DefaultCleanupDelay
}

// trackManagedRecord marks a record as actively managed in the current session
func (p *Provider) trackManagedRecord(host, domain string) {
	p.syncMu.Lock()
	defer p.syncMu.Unlock()

	if p.managedRecords == nil {
		p.managedRecords = make(map[string]struct{})
	}
	if p.syncZones == nil {
		p.syncZones = make(map[string]struct{})
	}

	key := host + ":" + domain
	p.managedRecords[key] = struct{}{}
	p.syncZones[domain] = struct{}{}
}

// startCleanupTimer starts or resets the debounced cleanup timer
func (p *Provider) startCleanupTimer() {
	p.syncMu.Lock()
	defer p.syncMu.Unlock()

	// Stop existing timer if running
	if p.syncTimer != nil {
		p.syncTimer.Stop()
	}

	// Start new timer
	p.syncTimer = time.AfterFunc(p.getCleanupDelay(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		p.cleanupOrphanedRecords(ctx)
	})
}

// cleanupOrphanedRecords deletes records that have our description but weren't touched this session
func (p *Provider) cleanupOrphanedRecords(ctx context.Context) {
	p.syncMu.Lock()
	zones := p.syncZones
	managed := p.managedRecords
	// Reset tracking for next session
	p.syncZones = make(map[string]struct{})
	p.managedRecords = make(map[string]struct{})
	p.syncMu.Unlock()

	if len(zones) == 0 {
		return
	}

	p.getLogger().Debug("starting orphan cleanup",
		zap.Int("managed_records", len(managed)),
		zap.Int("zones", len(zones)))

	// Query all hosts
	hosts, err := p.searchHosts(ctx)
	if err != nil {
		p.getLogger().Error("failed to search hosts for cleanup", zap.Error(err))
		return
	}

	needsReconfigure := false
	for _, h := range hosts {
		// Skip if not our description
		if h.Descr != p.getDescription() {
			continue
		}
		// Skip if not in a touched zone
		if _, ok := zones[h.Domain]; !ok {
			continue
		}
		// Skip if record was managed this session
		key := h.Host + ":" + h.Domain
		if _, ok := managed[key]; ok {
			continue
		}

		// Delete orphaned record
		p.getLogger().Info("deleting orphaned DNS record",
			zap.String("host", h.Host),
			zap.String("domain", h.Domain),
			zap.String("ip", h.IP))
		if err := p.deleteHost(ctx, h.UUID); err != nil {
			p.getLogger().Error("failed to delete orphaned host",
				zap.String("host", h.Host),
				zap.String("domain", h.Domain),
				zap.Error(err))
			continue
		}
		needsReconfigure = true
	}

	if needsReconfigure {
		if err := p.reconfigure(ctx); err != nil {
			p.getLogger().Error("failed to reconfigure after cleanup", zap.Error(err))
		}
	}

	p.getLogger().Debug("orphan cleanup completed")
}

// trimZone removes the trailing dot from a zone name
func trimZone(zone string) string {
	return strings.TrimSuffix(zone, ".")
}

// resolveHostAndDomain handles the special case where name is "@" (zone apex).
// For dnsmasq, we need to split the zone into host and domain parts.
// e.g., zone "my_domain.com" with name "@" becomes host "my_domain" and domain "com"
func resolveHostAndDomain(name, zone string) (host, domain string) {
	zone = trimZone(zone)
	if name == "@" || name == "" {
		// Zone apex: split the zone at the first dot
		if idx := strings.Index(zone, "."); idx > 0 {
			return zone[:idx], zone[idx+1:]
		}
		// No dot in zone, use zone as host with empty domain (edge case)
		return zone, ""
	}
	// Normal subdomain
	return name, zone
}

// hostToRecord converts a dnsmasqHost to a libdns.Address record
func hostToRecord(h dnsmasqHost) (libdns.Address, error) {
	ip, err := netip.ParseAddr(h.IP)
	if err != nil {
		return libdns.Address{}, fmt.Errorf("parsing IP %q: %w", h.IP, err)
	}

	return libdns.Address{
		Name: h.Host,
		IP:   ip,
	}, nil
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.getLogger().Debug("getting records", zap.String("zone", zone))

	hosts, err := p.searchHosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("searching hosts: %w", err)
	}

	zone = trimZone(zone)
	var records []libdns.Record

	for _, h := range hosts {
		var name string

		if h.Domain == zone {
			// Normal subdomain: host "example" in domain "my_domain.com"
			name = h.Host
		} else if h.Host+"."+h.Domain == zone {
			// Apex record: host "my_domain" in domain "com" for zone "my_domain.com"
			name = "@"
		} else {
			continue // not part of this zone
		}

		ip, err := netip.ParseAddr(h.IP)
		if err != nil {
			continue // skip invalid entries
		}

		// Determine record type for logging
		rr := "A"
		if ip.Is6() {
			rr = "AAAA"
		}

		p.getLogger().Debug("found DNS record",
			zap.String("type", rr),
			zap.String("name", name),
			zap.String("zone", zone),
			zap.String("value", ip.String()))

		records = append(records, libdns.Address{
			Name: name,
			IP:   ip,
		})
	}

	p.getLogger().Debug("finished getting records",
		zap.String("zone", zone),
		zap.Int("count", len(records)))

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.getLogger().Debug("appending records",
		zap.String("zone", zone),
		zap.Int("count", len(records)))

	var added []libdns.Record

	for _, record := range records {
		rr := record.RR()

		// Only A and AAAA records are supported
		if rr.Type != "A" && rr.Type != "AAAA" {
			return added, fmt.Errorf("unsupported record type %q: only A and AAAA are supported", rr.Type)
		}

		// Parse and validate the IP address
		ip, err := netip.ParseAddr(rr.Data)
		if err != nil {
			return added, fmt.Errorf("invalid IP address %q: %w", rr.Data, err)
		}

		// Get the relative name (hostname part) and resolve host/domain for dnsmasq
		name := libdns.RelativeName(rr.Name, zone)

		p.getLogger().Info("appending DNS record",
			zap.String("zone", zone),
			zap.String("name", name),
			zap.String("type", rr.Type),
			zap.String("ip", ip.String()))

		host, domain := resolveHostAndDomain(name, zone)

		if err := p.addHost(ctx, host, domain, ip.String()); err != nil {
			return added, fmt.Errorf("adding host %q: %w", name, err)
		}

		added = append(added, libdns.Address{
			Name: name,
			IP:   ip,
		})
	}

	if len(added) > 0 {
		if err := p.reconfigure(ctx); err != nil {
			return added, fmt.Errorf("reconfiguring: %w", err)
		}
	}

	return added, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.getLogger().Debug("setting records",
		zap.String("zone", zone),
		zap.Int("count", len(records)))

	// Get existing hosts
	existingHosts, err := p.searchHosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("searching hosts: %w", err)
	}

	// Build a map of existing hosts by host:domain key
	existingByKey := make(map[string]dnsmasqHost)
	for _, h := range existingHosts {
		key := h.Host + ":" + h.Domain
		existingByKey[key] = h
	}

	var results []libdns.Record
	needsReconfigure := false

	for _, record := range records {
		rr := record.RR()

		// Only A and AAAA records are supported
		if rr.Type != "A" && rr.Type != "AAAA" {
			return results, fmt.Errorf("unsupported record type %q: only A and AAAA are supported", rr.Type)
		}

		// Parse and validate the IP address
		ip, err := netip.ParseAddr(rr.Data)
		if err != nil {
			return results, fmt.Errorf("invalid IP address %q: %w", rr.Data, err)
		}

		name := libdns.RelativeName(rr.Name, zone)
		host, domain := resolveHostAndDomain(name, zone)
		key := host + ":" + domain

		// Track this record as managed for orphan cleanup
		p.trackManagedRecord(host, domain)

		// Check if an entry already exists
		if existing, ok := existingByKey[key]; ok {
			// Check if it's identical
			if existing.IP == ip.String() && existing.Descr == p.getDescription() {
				// Already correct, no changes needed
				p.getLogger().Debug("record already up to date",
					zap.String("zone", zone),
					zap.String("name", name),
					zap.String("type", rr.Type),
					zap.String("ip", ip.String()))
				results = append(results, libdns.Address{
					Name: name,
					IP:   ip,
				})
				continue
			}

			// Delete the old entry
			p.getLogger().Info("updating DNS record",
				zap.String("zone", zone),
				zap.String("name", name),
				zap.String("type", rr.Type),
				zap.String("old_ip", existing.IP),
				zap.String("new_ip", ip.String()))
			if err := p.deleteHost(ctx, existing.UUID); err != nil {
				return results, fmt.Errorf("deleting existing host %q: %w", name, err)
			}
		} else {
			p.getLogger().Info("creating DNS record",
				zap.String("zone", zone),
				zap.String("name", name),
				zap.String("type", rr.Type),
				zap.String("ip", ip.String()))
		}

		// Add the new entry
		if err := p.addHost(ctx, host, domain, ip.String()); err != nil {
			return results, fmt.Errorf("adding host %q: %w", name, err)
		}
		needsReconfigure = true

		results = append(results, libdns.Address{
			Name: name,
			IP:   ip,
		})
	}

	if needsReconfigure {
		if err := p.reconfigure(ctx); err != nil {
			return results, fmt.Errorf("reconfiguring: %w", err)
		}
	}

	// Start cleanup timer (will be reset if more SetRecords calls come in)
	p.startCleanupTimer()

	return results, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.getLogger().Debug("deleting records",
		zap.String("zone", zone),
		zap.Int("count", len(records)))

	// Get existing hosts
	existingHosts, err := p.searchHosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("searching hosts: %w", err)
	}

	// Build a map of existing hosts by host:domain key
	existingByKey := make(map[string]dnsmasqHost)
	for _, h := range existingHosts {
		key := h.Host + ":" + h.Domain
		existingByKey[key] = h
	}

	var deleted []libdns.Record

	for _, record := range records {
		rr := record.RR()
		name := libdns.RelativeName(rr.Name, zone)
		host, domain := resolveHostAndDomain(name, zone)
		key := host + ":" + domain

		existing, ok := existingByKey[key]
		if !ok {
			p.getLogger().Debug("record not found, skipping delete",
				zap.String("zone", zone),
				zap.String("name", name))
			continue // record doesn't exist, nothing to delete
		}

		p.getLogger().Info("deleting DNS record",
			zap.String("zone", zone),
			zap.String("name", name),
			zap.String("ip", existing.IP))

		if err := p.deleteHost(ctx, existing.UUID); err != nil {
			return deleted, fmt.Errorf("deleting host %q: %w", name, err)
		}

		addr, err := hostToRecord(existing)
		if err != nil {
			continue
		}
		deleted = append(deleted, addr)
	}

	if len(deleted) > 0 {
		if err := p.reconfigure(ctx); err != nil {
			return deleted, fmt.Errorf("reconfiguring: %w", err)
		}
	}

	return deleted, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
