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
)

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

	client     *http.Client
	clientOnce sync.Once
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
	defer resp.Body.Close()

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

	return nil
}

// trimZone removes the trailing dot from a zone name
func trimZone(zone string) string {
	return strings.TrimSuffix(zone, ".")
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
	hosts, err := p.searchHosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("searching hosts: %w", err)
	}

	domain := trimZone(zone)
	var records []libdns.Record

	for _, h := range hosts {
		if h.Domain != domain {
			continue
		}

		addr, err := hostToRecord(h)
		if err != nil {
			continue // skip invalid entries
		}
		records = append(records, addr)
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	domain := trimZone(zone)
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

		// Get the relative name (hostname part)
		name := libdns.RelativeName(rr.Name, zone)

		if err := p.addHost(ctx, name, domain, ip.String()); err != nil {
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
	domain := trimZone(zone)

	// Get existing hosts
	existingHosts, err := p.searchHosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("searching hosts: %w", err)
	}

	// Build a map of existing hosts by name for this domain
	existingByName := make(map[string]dnsmasqHost)
	for _, h := range existingHosts {
		if h.Domain == domain {
			existingByName[h.Host] = h
		}
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

		// Check if an entry already exists
		if existing, ok := existingByName[name]; ok {
			// Check if it's identical
			if existing.IP == ip.String() && existing.Descr == p.getDescription() {
				// Already correct, no changes needed
				results = append(results, libdns.Address{
					Name: name,
					IP:   ip,
				})
				continue
			}

			// Delete the old entry
			if err := p.deleteHost(ctx, existing.UUID); err != nil {
				return results, fmt.Errorf("deleting existing host %q: %w", name, err)
			}
			needsReconfigure = true
		}

		// Add the new entry
		if err := p.addHost(ctx, name, domain, ip.String()); err != nil {
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

	return results, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	domain := trimZone(zone)

	// Get existing hosts
	existingHosts, err := p.searchHosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("searching hosts: %w", err)
	}

	// Build a map of existing hosts by name for this domain
	existingByName := make(map[string]dnsmasqHost)
	for _, h := range existingHosts {
		if h.Domain == domain {
			existingByName[h.Host] = h
		}
	}

	var deleted []libdns.Record

	for _, record := range records {
		rr := record.RR()
		name := libdns.RelativeName(rr.Name, zone)

		existing, ok := existingByName[name]
		if !ok {
			continue // record doesn't exist, nothing to delete
		}

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
