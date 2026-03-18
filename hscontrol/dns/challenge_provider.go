package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
)

var (
	ErrUnsupportedDNSChallengeProvider = errors.New("unsupported DNS challenge provider")
	ErrDNSChallengeProviderDisabled    = errors.New("dns challenge provider disabled")
	ErrCloudflareTokenMissing          = errors.New("cloudflare api token is required")
	ErrCloudflareZoneMissing           = errors.New("cloudflare zone id is required")
	ErrCloudflareCreateRecordFailed    = errors.New("cloudflare create record failed")
	ErrCloudflareListRecordsFailed     = errors.New("cloudflare list records failed")
	ErrCloudflareDeleteRecordFailed    = errors.New("cloudflare delete record failed")
	ErrDNSPropagationTimeout           = errors.New("dns propagation timeout")
)

const (
	cloudflareProviderName         = "cloudflare"
	defaultCloudflareAPI           = "https://api.cloudflare.com/client/v4"
	defaultTXTTTLSeconds           = 120
	defaultPropagationTimeout      = 120 * time.Second
	defaultPropagationPollInterval = 5 * time.Second
	dnsLookupTimeout               = 10 * time.Second
)

// propagationResolvers are public DNS servers used to verify
// that a TXT record is visible before returning from UpsertTXT.
// We check multiple resolvers because Let's Encrypt may query any of them.
var propagationResolvers = []string{
	"1.1.1.1:53",
	"1.0.0.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
}

// ChallengeProvider creates and updates ACME DNS-01 TXT records.
type ChallengeProvider interface {
	UpsertTXT(ctx context.Context, fqdn, value string) error
}

// NewChallengeProvider creates a DNS challenge provider from configuration.
func NewChallengeProvider(cfg types.DNSChallengeConfig) (ChallengeProvider, error) {
	provider := strings.TrimSpace(strings.ToLower(cfg.Provider))
	if provider == "" {
		return nil, ErrDNSChallengeProviderDisabled
	}

	switch provider {
	case cloudflareProviderName:
		return newCloudflareProvider(cfg.Cloudflare)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedDNSChallengeProvider, cfg.Provider)
	}
}

type cloudflareProvider struct {
	client  *http.Client
	apiBase *url.URL
	zoneID  string
	token   string
}

func newCloudflareProvider(cfg types.CloudflareDNSChallengeConfig) (ChallengeProvider, error) {
	if strings.TrimSpace(cfg.APIToken) == "" {
		return nil, ErrCloudflareTokenMissing
	}

	if strings.TrimSpace(cfg.ZoneID) == "" {
		return nil, ErrCloudflareZoneMissing
	}

	apiURL := strings.TrimSpace(cfg.APIURL)
	if apiURL == "" {
		apiURL = defaultCloudflareAPI
	}

	parsed, err := url.Parse(apiURL)
	if err != nil {
		return nil, fmt.Errorf("parsing cloudflare api url: %w", err)
	}

	return &cloudflareProvider{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		apiBase: parsed,
		zoneID:  cfg.ZoneID,
		token:   cfg.APIToken,
	}, nil
}

func (p *cloudflareProvider) UpsertTXT(ctx context.Context, fqdn, value string) error {
	records, err := p.listTXTRecords(ctx, fqdn)
	if err != nil {
		return err
	}

	// Check if the exact value already exists.
	alreadyExists := false
	for _, rec := range records {
		if rec.Content == value {
			alreadyExists = true

			break
		}
	}

	if !alreadyExists {
		// Delete stale challenge TXT records to prevent accumulation.
		for _, rec := range records {
			delErr := p.deleteRecord(ctx, rec.ID)
			if delErr != nil {
				log.Warn().
					Err(delErr).
					Str("record_id", rec.ID).
					Str("fqdn", fqdn).
					Msg("failed to delete stale TXT record")
			}
		}

		err = p.createTXTRecord(ctx, fqdn, value)
		if err != nil {
			return err
		}
	}

	// Wait for DNS propagation before returning.
	// The Tailscale client calls ACME Accept immediately after SetDNS returns,
	// so the TXT record must be visible via public DNS at that point.
	return p.waitForPropagation(ctx, fqdn, value)
}

func (p *cloudflareProvider) createTXTRecord(ctx context.Context, fqdn, value string) error {
	createReq := map[string]any{
		"type":    "TXT",
		"name":    fqdn,
		"content": value,
		"ttl":     defaultTXTTTLSeconds,
	}

	body, err := json.Marshal(createReq)
	if err != nil {
		return fmt.Errorf("marshal cloudflare create request: %w", err)
	}

	requestURL := p.endpoint("dns_records")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create cloudflare create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("calling cloudflare create record: %w", err)
	}
	defer resp.Body.Close()

	var cfResp cloudflareResponse[json.RawMessage]

	err = json.NewDecoder(resp.Body).Decode(&cfResp)
	if err != nil {
		return fmt.Errorf("decode cloudflare create response: %w", err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices || !cfResp.Success {
		return fmt.Errorf(
			"%w: status=%d errors=%s",
			ErrCloudflareCreateRecordFailed,
			resp.StatusCode,
			cloudflareErrors(cfResp.Errors),
		)
	}

	log.Info().
		Str("fqdn", fqdn).
		Msg("created ACME challenge TXT record")

	return nil
}

func (p *cloudflareProvider) listTXTRecords(ctx context.Context, fqdn string) ([]cloudflareDNSRecord, error) {
	requestURL := p.endpoint("dns_records")
	query := requestURL.Query()
	query.Set("type", "TXT")
	query.Set("name", fqdn)
	requestURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create cloudflare list request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling cloudflare list records: %w", err)
	}
	defer resp.Body.Close()

	var cfResp cloudflareResponse[[]cloudflareDNSRecord]

	err = json.NewDecoder(resp.Body).Decode(&cfResp)
	if err != nil {
		return nil, fmt.Errorf("decode cloudflare list response: %w", err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices || !cfResp.Success {
		return nil, fmt.Errorf(
			"%w: status=%d errors=%s",
			ErrCloudflareListRecordsFailed,
			resp.StatusCode,
			cloudflareErrors(cfResp.Errors),
		)
	}

	return cfResp.Result, nil
}

func (p *cloudflareProvider) endpoint(resource string) *url.URL {
	u := *p.apiBase
	u.Path = path.Join(p.apiBase.Path, "zones", p.zoneID, resource)

	return &u
}

func (p *cloudflareProvider) deleteRecord(ctx context.Context, recordID string) error {
	requestURL := p.endpoint("dns_records/" + recordID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, requestURL.String(), nil)
	if err != nil {
		return fmt.Errorf("create cloudflare delete request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("calling cloudflare delete record: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf(
			"%w: status=%d record_id=%s",
			ErrCloudflareDeleteRecordFailed,
			resp.StatusCode,
			recordID,
		)
	}

	log.Debug().
		Str("record_id", recordID).
		Msg("deleted stale ACME challenge TXT record")

	return nil
}

// waitForPropagation polls public DNS resolvers until the TXT record
// is visible. This is critical because the Tailscale client calls
// ACME Accept immediately after SetDNS returns — if the record is not
// yet propagated, Let's Encrypt will reject the challenge.
func (p *cloudflareProvider) waitForPropagation(
	ctx context.Context,
	fqdn, value string,
) error {
	log.Info().
		Str("fqdn", fqdn).
		Dur("timeout", defaultPropagationTimeout).
		Msg("waiting for DNS propagation of ACME challenge TXT record")

	deadline := time.Now().Add(defaultPropagationTimeout)

	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		for _, server := range propagationResolvers {
			found, err := lookupTXTAt(ctx, fqdn, server)
			if err != nil {
				continue
			}

			if slices.Contains(found, value) {
				log.Info().
					Str("fqdn", fqdn).
					Str("resolver", server).
					Msg("DNS propagation confirmed")

				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(defaultPropagationPollInterval):
		}
	}

	return fmt.Errorf(
		"%w: TXT record %q not visible via public DNS after %s",
		ErrDNSPropagationTimeout,
		fqdn,
		defaultPropagationTimeout,
	)
}

// lookupTXTAt queries a specific DNS server for TXT records.
func lookupTXTAt(ctx context.Context, fqdn, nameserver string) ([]string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: dnsLookupTimeout}

			return d.DialContext(ctx, "udp", nameserver)
		},
	}

	lookupCtx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()

	return resolver.LookupTXT(lookupCtx, fqdn)
}

type cloudflareResponse[T any] struct {
	Success bool                 `json:"success"`
	Errors  []cloudflareAPIError `json:"errors"`
	Result  T                    `json:"result"`
}

type cloudflareAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cloudflareDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

func cloudflareErrors(errs []cloudflareAPIError) string {
	if len(errs) == 0 {
		return "none"
	}

	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, fmt.Sprintf("%d:%s", e.Code, e.Message))
	}

	return strings.Join(parts, ",")
}
