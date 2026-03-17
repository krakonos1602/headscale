package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
)

var (
	ErrUnsupportedDNSChallengeProvider = errors.New("unsupported DNS challenge provider")
	ErrDNSChallengeProviderDisabled    = errors.New("dns challenge provider disabled")
	ErrCloudflareTokenMissing          = errors.New("cloudflare api token is required")
	ErrCloudflareZoneMissing           = errors.New("cloudflare zone id is required")
	ErrCloudflareCreateRecordFailed    = errors.New("cloudflare create record failed")
	ErrCloudflareListRecordsFailed     = errors.New("cloudflare list records failed")
)

const (
	cloudflareProviderName = "cloudflare"
	defaultCloudflareAPI   = "https://api.cloudflare.com/client/v4"
	defaultTXTTTLSeconds   = 120
)

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

	for _, rec := range records {
		if rec.Content == value {
			return nil
		}
	}

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
