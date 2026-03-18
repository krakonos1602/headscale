package dns

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testDNSRecordsPath = "/client/v4/zones/test-zone/dns_records"

func TestDeleteTXTValueDeletesOnlyMatchingRecords(t *testing.T) {
	t.Parallel()

	var (
		mu         sync.Mutex
		deletedIDs []string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == testDNSRecordsPath:
			_ = json.NewEncoder(w).Encode(cloudflareResponse[[]cloudflareDNSRecord]{
				Success: true,
				Result: []cloudflareDNSRecord{
					{ID: "keep", Name: "_acme-challenge.node.example.com", Content: "keep-me"},
					{ID: "delete-1", Name: "_acme-challenge.node.example.com", Content: "delete-me"},
					{ID: "delete-2", Name: "_acme-challenge.node.example.com", Content: "delete-me"},
				},
			})
		case r.Method == http.MethodDelete:
			mu.Lock()

			deletedIDs = append(deletedIDs, r.URL.Path)
			mu.Unlock()

			_ = json.NewEncoder(w).Encode(cloudflareResponse[json.RawMessage]{Success: true})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	provider := newTestCloudflareProvider(t, server)

	err := provider.deleteTXTValue(context.Background(), "_acme-challenge.node.example.com", "delete-me")
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()

	require.ElementsMatch(t, []string{
		testDNSRecordsPath + "/delete-1",
		testDNSRecordsPath + "/delete-2",
	}, deletedIDs)
}

func TestScheduleCleanupDeletesRecordAfterDelay(t *testing.T) {
	t.Parallel()

	deleted := make(chan string, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == testDNSRecordsPath:
			_ = json.NewEncoder(w).Encode(cloudflareResponse[[]cloudflareDNSRecord]{
				Success: true,
				Result: []cloudflareDNSRecord{{
					ID:      "delete-later",
					Name:    "_acme-challenge.node.example.com",
					Content: "token-value",
				}},
			})
		case r.Method == http.MethodDelete:
			deleted <- r.URL.Path

			_ = json.NewEncoder(w).Encode(cloudflareResponse[json.RawMessage]{Success: true})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	provider := newTestCloudflareProvider(t, server)
	provider.cleanupDelay = 10 * time.Millisecond

	provider.scheduleCleanup(context.Background(), "_acme-challenge.node.example.com", "token-value")

	select {
	case got := <-deleted:
		require.Equal(t, testDNSRecordsPath+"/delete-later", got)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for cleanup")
	}
}

func TestUpsertTXTDeletesStaleRecordsBeforeCreate(t *testing.T) {
	t.Parallel()

	var (
		mu          sync.Mutex
		deletedIDs  []string
		createdBody map[string]any
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == testDNSRecordsPath:
			_ = json.NewEncoder(w).Encode(cloudflareResponse[[]cloudflareDNSRecord]{
				Success: true,
				Result: []cloudflareDNSRecord{{
					ID:      "stale-record",
					Name:    "_acme-challenge.node.example.com",
					Content: "old-token",
				}},
			})
		case r.Method == http.MethodDelete:
			mu.Lock()

			deletedIDs = append(deletedIDs, r.URL.Path)
			mu.Unlock()

			_ = json.NewEncoder(w).Encode(cloudflareResponse[json.RawMessage]{Success: true})
		case r.Method == http.MethodPost && r.URL.Path == testDNSRecordsPath:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("reading request body: %v", err)
				w.WriteHeader(http.StatusInternalServerError)

				return
			}

			defer r.Body.Close()

			mu.Lock()
			err = json.Unmarshal(body, &createdBody)
			mu.Unlock()

			if err != nil {
				t.Errorf("unmarshaling create request: %v", err)
				w.WriteHeader(http.StatusInternalServerError)

				return
			}

			_ = json.NewEncoder(w).Encode(cloudflareResponse[json.RawMessage]{Success: true})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	provider := newTestCloudflareProvider(t, server)
	provider.cleanupDelay = time.Hour
	provider.propagationResolvers = []string{"resolver.test:53"}
	provider.propagationTimeout = 100 * time.Millisecond
	provider.propagationPollInterval = 10 * time.Millisecond
	provider.lookupTXT = func(context.Context, string, string) ([]string, error) {
		return []string{"new-token"}, nil
	}

	err := provider.UpsertTXT(context.Background(), "_acme-challenge.node.example.com", "new-token")
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()

	require.Equal(t, []string{testDNSRecordsPath + "/stale-record"}, deletedIDs)
	require.Equal(t, "TXT", createdBody["type"])
	require.Equal(t, "_acme-challenge.node.example.com", createdBody["name"])
	require.Equal(t, "new-token", createdBody["content"])
	require.EqualValues(t, defaultTXTTTLSeconds, createdBody["ttl"])
}

func newTestCloudflareProvider(t *testing.T, server *httptest.Server) *cloudflareProvider {
	t.Helper()

	parsed, err := url.Parse(server.URL + "/client/v4")
	require.NoError(t, err)

	return &cloudflareProvider{
		client:                  server.Client(),
		apiBase:                 parsed,
		zoneID:                  "test-zone",
		token:                   "token",
		propagationResolvers:    propagationResolvers,
		propagationTimeout:      defaultPropagationTimeout,
		propagationPollInterval: defaultPropagationPollInterval,
		cleanupDelay:            defaultCleanupDelay,
		lookupTXT:               lookupTXTAt,
	}
}
