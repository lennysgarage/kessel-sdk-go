package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestMakeOAuth2ClientCredentials(t *testing.T) {
	clientId := "test-client-id"
	clientSecret := "test-client-secret"
	tokenEndpoint := "https://example.com/token"

	credentials := NewOAuth2ClientCredentials(clientId, clientSecret, tokenEndpoint)

	if credentials.clientId != clientId {
		t.Errorf("Expected clientId to be %s, got %s", clientId, credentials.clientId)
	}
	if credentials.clientSecret != clientSecret {
		t.Errorf("Expected clientSecret to be %s, got %s", clientSecret, credentials.clientSecret)
	}
	if credentials.tokenEndpoint != tokenEndpoint {
		t.Errorf("Expected tokenEndpoint to be %s, got %s", tokenEndpoint, credentials.tokenEndpoint)
	}
	if credentials.cachedToken.AccessToken != "" {
		t.Errorf("Expected cached token to be empty initially")
	}
}

func TestNewOAuth2ClientCredentials_retry_option_behavior(t *testing.T) {
	tests := []struct {
		name          string
		opts          []RetryOption
		failCount     int
		expectSuccess bool
		expectedCalls int
	}{
		{
			name:          "no options uses default 3 retries",
			opts:          nil,
			failCount:     3,
			expectSuccess: true,
			expectedCalls: 4, // 1 initial + 3 retries
		},
		{
			name:          "WithMaxRetries(0) disables retries",
			opts:          []RetryOption{WithMaxRetries(0)},
			failCount:     1,
			expectSuccess: false,
			expectedCalls: 1,
		},
		{
			name:          "WithJitter only retains default retry count",
			opts:          []RetryOption{WithJitter(JitterNone)},
			failCount:     2,
			expectSuccess: true,
			expectedCalls: 3, // 1 initial + 2 retries (default 3 retries available)
		},
		{
			name:          "WithBaseDelay only retains default retry count",
			opts:          []RetryOption{WithBaseDelay(0.01)},
			failCount:     3,
			expectSuccess: true,
			expectedCalls: 4,
		},
		{
			name:          "WithMaxRetries overrides default",
			opts:          []RetryOption{WithMaxRetries(5)},
			failCount:     5,
			expectSuccess: true,
			expectedCalls: 6, // 1 initial + 5 retries
		},
		{
			name:          "combined partial options retain unset defaults",
			opts:          []RetryOption{WithJitter(JitterNone), WithBaseDelay(0.01)},
			failCount:     3,
			expectSuccess: true,
			expectedCalls: 4, // default 3 retries retained
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callCount := 0
			var mu sync.Mutex
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				callCount++
				current := callCount
				mu.Unlock()

				if current <= tt.failCount {
					http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "ok",
					"token_type":   "Bearer",
					"expires_in":   3600,
				}); err != nil {
					t.Errorf("Failed to encode test response: %v", err)
				}
			}))
			defer server.Close()

			// Use fast delays to keep tests quick and deterministic
			allOpts := append([]RetryOption{WithBaseDelay(0.01), WithMaxDelay(0.02)}, tt.opts...)
			credentials := NewOAuth2ClientCredentials("client", "secret", server.URL, allOpts...)

			resp, err := credentials.GetToken(context.Background(), GetTokenOptions{})

			if tt.expectSuccess {
				if err != nil {
					t.Fatalf("Expected success, got error: %v", err)
				}
				if resp.AccessToken != "ok" {
					t.Errorf("Expected token %q, got %q", "ok", resp.AccessToken)
				}
			} else {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
			}

			mu.Lock()
			final := callCount
			mu.Unlock()
			if final != tt.expectedCalls {
				t.Errorf("Expected %d token requests, got %d", tt.expectedCalls, final)
			}
		})
	}
}

func TestFetchOIDCDiscovery(t *testing.T) {
	tests := []struct {
		name         string
		options      FetchOIDCDiscoveryOptions
		expectError  bool
		errorMessage string
	}{
		{
			name:        "invalid issuer URL",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FetchOIDCDiscovery(context.TODO(), "invalid-url", FetchOIDCDiscoveryOptions{})
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				if tt.errorMessage != "" && err != nil && err.Error() != tt.errorMessage {
					t.Errorf("Expected error message '%s', got '%s'", tt.errorMessage, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestFetchOIDCDiscovery_DefaultValues(t *testing.T) {
	// Test with nil context and http client (should use defaults)
	options := FetchOIDCDiscoveryOptions{
		HttpClient: nil,
	}

	// This should fail gracefully, but we're testing that defaults are applied
	_, err := FetchOIDCDiscovery(context.TODO(), "invalid-url-for-testing", options)
	if err == nil {
		t.Errorf("Expected error with invalid URL")
	}
	// The main thing we're testing is that it doesn't panic with nil values
}

func TestOAuth2ClientCredentials_GetToken(t *testing.T) {
	tests := []struct {
		name          string
		setupToken    *RefreshTokenResponse
		options       GetTokenOptions
		serverHandler func(w http.ResponseWriter, r *http.Request)
		expectError   bool
		expectRefresh bool
	}{
		{
			name: "use cached valid token",
			setupToken: &RefreshTokenResponse{
				AccessToken: "cached-token",
				ExpiresAt:   time.Now().Add(time.Hour),
			},
			options: GetTokenOptions{
				ForceRefresh: false,
			},
			expectError:   false,
			expectRefresh: false,
		},
		{
			name: "force refresh token",
			setupToken: &RefreshTokenResponse{
				AccessToken: "cached-token",
				ExpiresAt:   time.Now().Add(time.Hour),
			},
			options: GetTokenOptions{
				ForceRefresh: true,
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"access_token": "new-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(response); err != nil {
					t.Errorf("Failed to encode test response: %v", err)
				}
			},
			expectError:   false,
			expectRefresh: true,
		},
		{
			name:       "refresh expired token",
			setupToken: nil, // No cached token
			options: GetTokenOptions{
				ForceRefresh: false,
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"access_token": "fresh-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(response); err != nil {
					t.Errorf("Failed to encode test response: %v", err)
				}
			},
			expectError:   false,
			expectRefresh: true,
		},
		{
			name:       "server error during refresh",
			setupToken: nil,
			options: GetTokenOptions{
				ForceRefresh: false,
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			},
			expectError:   true,
			expectRefresh: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *httptest.Server
			if tt.serverHandler != nil {
				server = httptest.NewServer(http.HandlerFunc(tt.serverHandler))
				defer server.Close()
			}

			tokenEndpoint := ""
			if server != nil {
				tokenEndpoint = server.URL
			}

			// Disable retries so existing tests behave identically
			credentials := NewOAuth2ClientCredentials("test-client", "test-secret", tokenEndpoint, WithMaxRetries(0))

			// Setup cached token if provided
			if tt.setupToken != nil {
				credentials.cachedToken = *tt.setupToken
			}

			if tt.options.HttpClient == nil {
				tt.options.HttpClient = http.DefaultClient
			}

			result, err := credentials.GetToken(context.TODO(), tt.options)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				if tt.expectRefresh {
					if tt.name == "force refresh token" && result.AccessToken != "new-token" {
						t.Errorf("Expected new token 'new-token', got '%s'", result.AccessToken)
					}
					if tt.name == "refresh expired token" && result.AccessToken != "fresh-token" {
						t.Errorf("Expected fresh token 'fresh-token', got '%s'", result.AccessToken)
					}
				} else {
					if result.AccessToken != "cached-token" {
						t.Errorf("Expected cached token 'cached-token', got '%s'", result.AccessToken)
					}
				}
			}
		})
	}
}

func TestOAuth2ClientCredentials_GetToken_DefaultValues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("Failed to encode test response: %v", err)
		}
	}))
	defer server.Close()

	credentials := NewOAuth2ClientCredentials("test-client", "test-secret", server.URL)

	// Test with nil context and http client (should use defaults)
	options := GetTokenOptions{
		ForceRefresh: false,
		HttpClient:   nil,
	}

	result, err := credentials.GetToken(context.TODO(), options)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result.AccessToken != "test-token" {
		t.Errorf("Expected access token 'test-token', got '%s'", result.AccessToken)
	}
}

func TestOAuth2ClientCredentials_isTokenValid(t *testing.T) {
	tests := []struct {
		name        string
		token       RefreshTokenResponse
		expectValid bool
	}{
		{
			name: "valid token",
			token: RefreshTokenResponse{
				AccessToken: "valid-token",
				ExpiresAt:   time.Now().Add(time.Hour),
			},
			expectValid: true,
		},
		{
			name: "expired token",
			token: RefreshTokenResponse{
				AccessToken: "expired-token",
				ExpiresAt:   time.Now().Add(-time.Hour),
			},
			expectValid: false,
		},
		{
			name: "token expiring soon",
			token: RefreshTokenResponse{
				AccessToken: "expiring-soon-token",
				ExpiresAt:   time.Now().Add(time.Minute), // Less than expiration window (5 minutes)
			},
			expectValid: false,
		},
		{
			name: "empty token",
			token: RefreshTokenResponse{
				AccessToken: "",
				ExpiresAt:   time.Now().Add(time.Hour),
			},
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credentials := NewOAuth2ClientCredentials("test-client", "test-secret", "https://example.com/token")
			credentials.cachedToken = tt.token

			result := credentials.isTokenValid()
			if result != tt.expectValid {
				t.Errorf("Expected isTokenValid to return %v, got %v", tt.expectValid, result)
			}
		})
	}
}

func TestOAuth2ClientCredentials_refreshToken(t *testing.T) {
	tests := []struct {
		name          string
		serverHandler func(w http.ResponseWriter, r *http.Request)
		expectError   bool
		expectedToken string
		expectedTime  bool // Whether to check if time is set properly
	}{
		{
			name: "successful token refresh",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"access_token": "new-access-token",
					"token_type":   "Bearer",
					"expires_in":   7200,
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(response); err != nil {
					t.Errorf("Failed to encode test response: %v", err)
				}
			},
			expectError:   false,
			expectedToken: "new-access-token",
			expectedTime:  true,
		},
		{
			name: "token refresh with default expires_in",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"access_token": "default-token",
					"token_type":   "Bearer",
					// No expires_in field - should use default
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(response); err != nil {
					t.Errorf("Failed to encode test response: %v", err)
				}
			},
			expectError:   false,
			expectedToken: "default-token",
			expectedTime:  true,
		},
		{
			name: "server error",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.serverHandler))
			defer server.Close()

			credentials := NewOAuth2ClientCredentials("test-client", "test-secret", server.URL)

			result, err := credentials.refreshToken(context.Background(), http.DefaultClient)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result.AccessToken != tt.expectedToken {
					t.Errorf("Expected access token '%s', got '%s'", tt.expectedToken, result.AccessToken)
				}
				if tt.expectedTime && result.ExpiresAt.Before(time.Now()) {
					t.Errorf("Expected expiration time to be in the future")
				}
			}
		})
	}
}

func TestOAuth2ClientCredentials_refreshToken_UsesActualExpiry(t *testing.T) {
	tests := []struct {
		name             string
		expiresIn        int
		includeExpiresIn bool
		expectedLifetime time.Duration
	}{
		{
			name:             "uses 900 second expiry",
			expiresIn:        900,
			includeExpiresIn: true,
			expectedLifetime: 900 * time.Second,
		},
		{
			name:             "uses 120 second expiry",
			expiresIn:        120,
			includeExpiresIn: true,
			expectedLifetime: 120 * time.Second,
		},
		{
			name:             "uses 3600 second expiry",
			expiresIn:        3600,
			includeExpiresIn: true,
			expectedLifetime: 3600 * time.Second,
		},
		{
			name:             "defaults when expires_in is zero",
			expiresIn:        0,
			includeExpiresIn: true,
			expectedLifetime: defaultExpiresIn * time.Second,
		},
		{
			name:             "defaults when expires_in is missing",
			expectedLifetime: defaultExpiresIn * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"access_token": "test-token",
					"token_type":   "Bearer",
				}
				if tt.includeExpiresIn {
					response["expires_in"] = tt.expiresIn
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(response); err != nil {
					t.Errorf("Failed to encode test response: %v", err)
				}
			}))
			defer server.Close()

			credentials := NewOAuth2ClientCredentials("test-client", "test-secret", server.URL, WithMaxRetries(0))

			start := time.Now()
			result, err := credentials.refreshToken(context.Background(), http.DefaultClient)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			lifetime := result.ExpiresAt.Sub(start)
			if lifetime < tt.expectedLifetime-2*time.Second || lifetime > tt.expectedLifetime+2*time.Second {
				t.Errorf("Expected token lifetime %s, got %s", tt.expectedLifetime, lifetime)
			}
		})
	}
}

func TestOauth2TokenEndpointCaller(t *testing.T) {
	tokenEndpoint := "https://example.com/token"
	httpClient := &http.Client{}

	caller := oauth2TokenEndpointCaller{
		tokenEndpoint: tokenEndpoint,
		httpClient:    httpClient,
	}

	if caller.TokenEndpoint() != tokenEndpoint {
		t.Errorf("Expected TokenEndpoint() to return '%s', got '%s'", tokenEndpoint, caller.TokenEndpoint())
	}

	if caller.HttpClient() != httpClient {
		t.Errorf("Expected HttpClient() to return the same client instance")
	}
}

func TestConcurrentTokenAccess(t *testing.T) {
	callCount := 0
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		response := map[string]interface{}{
			"access_token": "shared-token-123",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("Failed to encode test response: %v", err)
		}
	}))
	defer server.Close()

	credentials := NewOAuth2ClientCredentials("test-client", "test-secret", server.URL)

	const numGoroutines = 20
	results := make(chan RefreshTokenResponse, numGoroutines)
	errors := make(chan error, numGoroutines)

	var ready sync.WaitGroup
	ready.Add(numGoroutines)
	gate := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		go func() {
			ready.Done()
			<-gate
			token, err := credentials.GetToken(context.TODO(), GetTokenOptions{})
			if err != nil {
				errors <- err
			} else {
				results <- token
			}
		}()
	}

	ready.Wait()
	close(gate)

	var tokens []RefreshTokenResponse
	for i := 0; i < numGoroutines; i++ {
		select {
		case token := <-results:
			tokens = append(tokens, token)
		case err := <-errors:
			t.Errorf("Unexpected error in concurrent access: %v", err)
		case <-time.After(10 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations to complete")
		}
	}

	if len(tokens) != numGoroutines {
		t.Errorf("Expected %d tokens, got %d", numGoroutines, len(tokens))
	}

	for i, token := range tokens {
		if token.AccessToken != "shared-token-123" {
			t.Errorf("Token %d: expected 'shared-token-123', got '%s'", i, token.AccessToken)
		}
	}

	mu.Lock()
	finalCallCount := callCount
	mu.Unlock()

	if finalCallCount != 1 {
		t.Errorf("Thundering herd: SSO was called %d times, expected exactly 1", finalCallCount)
	}
}

func TestConcurrentTokenAccess_stale_token(t *testing.T) {
	callCount := 0
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		response := map[string]interface{}{
			"access_token": "refreshed-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("Failed to encode test response: %v", err)
		}
	}))
	defer server.Close()

	credentials := NewOAuth2ClientCredentials("test-client", "test-secret", server.URL)
	credentials.cachedToken = RefreshTokenResponse{
		AccessToken: "stale-token",
		ExpiresAt:   time.Now().Add(60 * time.Second), // inside the 300s early-refresh window
	}

	const numGoroutines = 20
	results := make(chan RefreshTokenResponse, numGoroutines)
	errors := make(chan error, numGoroutines)

	var ready sync.WaitGroup
	ready.Add(numGoroutines)
	gate := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		go func() {
			ready.Done()
			<-gate
			token, err := credentials.GetToken(context.TODO(), GetTokenOptions{})
			if err != nil {
				errors <- err
			} else {
				results <- token
			}
		}()
	}

	ready.Wait()
	close(gate)

	var tokens []RefreshTokenResponse
	for i := 0; i < numGoroutines; i++ {
		select {
		case token := <-results:
			tokens = append(tokens, token)
		case err := <-errors:
			t.Errorf("Unexpected error in concurrent access: %v", err)
		case <-time.After(10 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations to complete")
		}
	}

	if len(tokens) != numGoroutines {
		t.Errorf("Expected %d tokens, got %d", numGoroutines, len(tokens))
	}

	for i, token := range tokens {
		if token.AccessToken != "refreshed-token" {
			t.Errorf("Token %d: expected 'refreshed-token', got '%s'", i, token.AccessToken)
		}
	}

	mu.Lock()
	finalCallCount := callCount
	mu.Unlock()

	if finalCallCount != 1 {
		t.Errorf("Thundering herd: SSO was called %d times, expected exactly 1", finalCallCount)
	}
}

func TestConcurrentForceRefresh(t *testing.T) {
	callCount := 0
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		response := map[string]interface{}{
			"access_token": "force-refreshed-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("Failed to encode test response: %v", err)
		}
	}))
	defer server.Close()

	credentials := NewOAuth2ClientCredentials("test-client", "test-secret", server.URL)
	credentials.cachedToken = RefreshTokenResponse{
		AccessToken: "old-token",
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	const numGoroutines = 20
	results := make(chan RefreshTokenResponse, numGoroutines)
	errors := make(chan error, numGoroutines)

	var ready sync.WaitGroup
	ready.Add(numGoroutines)
	gate := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		go func() {
			ready.Done()
			<-gate
			token, err := credentials.GetToken(context.TODO(), GetTokenOptions{ForceRefresh: true})
			if err != nil {
				errors <- err
			} else {
				results <- token
			}
		}()
	}

	ready.Wait()
	close(gate)

	var tokens []RefreshTokenResponse
	for i := 0; i < numGoroutines; i++ {
		select {
		case token := <-results:
			tokens = append(tokens, token)
		case err := <-errors:
			t.Errorf("Unexpected error in concurrent access: %v", err)
		case <-time.After(10 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations to complete")
		}
	}

	if len(tokens) != numGoroutines {
		t.Errorf("Expected %d tokens, got %d", numGoroutines, len(tokens))
	}

	for i, token := range tokens {
		if token.AccessToken != "force-refreshed-token" {
			t.Errorf("Token %d: expected 'force-refreshed-token', got '%s'", i, token.AccessToken)
		}
	}

	mu.Lock()
	finalCallCount := callCount
	mu.Unlock()

	if finalCallCount != 1 {
		t.Errorf("Thundering herd: SSO was called %d times, expected exactly 1", finalCallCount)
	}
}

// --- Retry-specific tests ---

func TestRetryDelay_full_jitter(t *testing.T) {
	credentials := NewOAuth2ClientCredentials("id", "secret", "https://example.com/token")

	tests := []struct {
		name       string
		retryIndex int
		maxCap     float64 // expected upper bound in seconds
	}{
		{"retry 0", 0, 0.5},
		{"retry 1", 1, 1.0},
		{"retry 2", 2, 2.0},
		{"retry 3", 3, 2.0}, // capped at maxDelay
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < 100; i++ {
				delay := credentials.retryDelay(tt.retryIndex)
				if delay < 0 {
					t.Errorf("Delay must be non-negative, got %v", delay)
				}
				maxDuration := time.Duration(tt.maxCap * float64(time.Second))
				if delay > maxDuration {
					t.Errorf("Delay %v exceeds cap %v", delay, maxDuration)
				}
			}
		})
	}
}

func TestRetryDelay_no_jitter(t *testing.T) {
	credentials := NewOAuth2ClientCredentials("id", "secret", "https://example.com/token",
		WithMaxRetries(3), WithBaseDelay(0.5), WithMaxDelay(2.0), WithJitter(JitterNone))

	tests := []struct {
		name       string
		retryIndex int
		expected   time.Duration
	}{
		{"retry 0", 0, 500 * time.Millisecond},
		{"retry 1", 1, 1000 * time.Millisecond},
		{"retry 2", 2, 2000 * time.Millisecond},
		{"retry 3", 3, 2000 * time.Millisecond}, // capped at maxDelay
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delay := credentials.retryDelay(tt.retryIndex)
			if delay != tt.expected {
				t.Errorf("Expected delay %v, got %v", tt.expected, delay)
			}
		})
	}
}

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		httpStatus int
		expected   bool
	}{
		{
			name:       "network error",
			err:        &net.OpError{Op: "dial", Err: fmt.Errorf("connection refused")},
			httpStatus: 0,
			expected:   true,
		},
		{
			name:       "dns error",
			err:        &net.DNSError{Err: "no such host", Name: "example.com"},
			httpStatus: 0,
			expected:   true,
		},
		{
			name:       "http 429",
			err:        fmt.Errorf("rate limited"),
			httpStatus: 429,
			expected:   true,
		},
		{
			name:       "http 500",
			err:        fmt.Errorf("server error"),
			httpStatus: 500,
			expected:   true,
		},
		{
			name:       "http 502",
			err:        fmt.Errorf("bad gateway"),
			httpStatus: 502,
			expected:   true,
		},
		{
			name:       "http 503",
			err:        fmt.Errorf("service unavailable"),
			httpStatus: 503,
			expected:   true,
		},
		{
			name:       "http 599",
			err:        fmt.Errorf("unknown server error"),
			httpStatus: 599,
			expected:   true,
		},
		{
			name:       "http 400 not retryable",
			err:        fmt.Errorf("bad request"),
			httpStatus: 400,
			expected:   false,
		},
		{
			name:       "http 401 not retryable",
			err:        fmt.Errorf("unauthorized"),
			httpStatus: 401,
			expected:   false,
		},
		{
			name:       "http 403 not retryable",
			err:        fmt.Errorf("forbidden"),
			httpStatus: 403,
			expected:   false,
		},
		{
			name:       "generic error not retryable",
			err:        fmt.Errorf("something went wrong"),
			httpStatus: 0,
			expected:   false,
		},
		{
			name: "url error wrapping unsupported scheme not retryable",
			err: &url.Error{
				Op:  "Get",
				URL: "ftp://example.com/token",
				Err: errors.New("unsupported protocol scheme \"ftp\""),
			},
			httpStatus: 0,
			expected:   false,
		},
		{
			name: "url error wrapping context canceled not retryable",
			err: &url.Error{
				Op:  "Get",
				URL: "https://example.com/token",
				Err: context.Canceled,
			},
			httpStatus: 0,
			expected:   false,
		},
		{
			name: "url error wrapping net error is retryable",
			err: &url.Error{
				Op:  "Get",
				URL: "https://example.com/token",
				Err: &net.OpError{Op: "dial", Err: fmt.Errorf("connection refused")},
			},
			httpStatus: 0,
			expected:   true,
		},
		{
			name: "url error wrapping eof is retryable",
			err: &url.Error{
				Op:  "Post",
				URL: "https://example.com/token",
				Err: io.EOF,
			},
			httpStatus: 0,
			expected:   true,
		},
		{
			name: "url error wrapping unexpected eof is retryable",
			err: &url.Error{
				Op:  "Post",
				URL: "https://example.com/token",
				Err: io.ErrUnexpectedEOF,
			},
			httpStatus: 0,
			expected:   true,
		},
		{
			name: "url error wrapping wrapped eof is retryable",
			err: &url.Error{
				Op:  "Post",
				URL: "https://example.com/token",
				Err: fmt.Errorf("read body: %w", io.EOF),
			},
			httpStatus: 0,
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRetryableError(tt.err, tt.httpStatus)
			if result != tt.expected {
				t.Errorf("Expected isRetryableError to return %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestStatusCapturingTransport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	capture := &statusCapturingTransport{base: http.DefaultTransport}
	client := &http.Client{Transport: capture}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Errorf("Failed to close body: %v", err)
	}

	if capture.lastStatus != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, capture.lastStatus)
	}
}

func TestStatusCapturingTransport_network_error(t *testing.T) {
	capture := &statusCapturingTransport{base: http.DefaultTransport}
	client := &http.Client{Transport: capture}

	// Connect to a port that should refuse connections
	_, err := client.Get("http://127.0.0.1:1")
	if err == nil {
		t.Fatal("Expected error but got none")
	}

	if capture.lastStatus != 0 {
		t.Errorf("Expected status 0 on network error, got %d", capture.lastStatus)
	}
}

func TestRefreshTokenWithRetries_success_first_attempt(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "token-ok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}); err != nil {
			t.Errorf("Failed to encode test response: %v", err)
		}
	}))
	defer server.Close()

	credentials := NewOAuth2ClientCredentials("client", "secret", server.URL)
	resp, err := credentials.refreshTokenWithRetries(context.Background(), http.DefaultClient)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.AccessToken != "token-ok" {
		t.Errorf("Expected 'token-ok', got %q", resp.AccessToken)
	}
	if callCount != 1 {
		t.Errorf("Expected 1 call, got %d", callCount)
	}
}

func TestRefreshTokenWithRetries_http_status_codes(t *testing.T) {
	tests := []struct {
		name          string
		failStatus    int
		failCount     int
		maxRetries    int
		expectSuccess bool
		expectedCalls int
	}{
		{
			name:          "retry on 500 then succeed",
			failStatus:    http.StatusInternalServerError,
			failCount:     2,
			maxRetries:    3,
			expectSuccess: true,
			expectedCalls: 3,
		},
		{
			name:          "retry on 429 then succeed",
			failStatus:    http.StatusTooManyRequests,
			failCount:     1,
			maxRetries:    3,
			expectSuccess: true,
			expectedCalls: 2,
		},
		{
			name:          "retry on 502 then succeed",
			failStatus:    http.StatusBadGateway,
			failCount:     1,
			maxRetries:    3,
			expectSuccess: true,
			expectedCalls: 2,
		},
		{
			name:          "no retry on 401",
			failStatus:    http.StatusUnauthorized,
			failCount:     1,
			maxRetries:    3,
			expectSuccess: false,
			expectedCalls: 1,
		},
		{
			name:          "no retry on 400",
			failStatus:    http.StatusBadRequest,
			failCount:     1,
			maxRetries:    3,
			expectSuccess: false,
			expectedCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callCount := 0
			var mu sync.Mutex
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				callCount++
				current := callCount
				mu.Unlock()

				if current <= tt.failCount {
					http.Error(w, http.StatusText(tt.failStatus), tt.failStatus)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "recovered",
					"token_type":   "Bearer",
					"expires_in":   3600,
				}); err != nil {
					t.Errorf("Failed to encode test response: %v", err)
				}
			}))
			defer server.Close()

			credentials := NewOAuth2ClientCredentials("client", "secret", server.URL,
				WithMaxRetries(tt.maxRetries), WithBaseDelay(0.01), WithMaxDelay(0.02), WithJitter(JitterNone))
			resp, err := credentials.refreshTokenWithRetries(context.Background(), http.DefaultClient)

			if tt.expectSuccess {
				if err != nil {
					t.Fatalf("Expected success, got error: %v", err)
				}
				if resp.AccessToken != "recovered" {
					t.Errorf("Expected token %q, got %q", "recovered", resp.AccessToken)
				}
			} else {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
			}

			mu.Lock()
			final := callCount
			mu.Unlock()
			if final != tt.expectedCalls {
				t.Errorf("Expected %d calls, got %d", tt.expectedCalls, final)
			}
		})
	}
}

func TestRefreshTokenWithRetries_max_retries_exceeded(t *testing.T) {
	callCount := 0
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	credentials := NewOAuth2ClientCredentials("client", "secret", server.URL,
		WithMaxRetries(2), WithBaseDelay(0.01), WithMaxDelay(0.02), WithJitter(JitterNone))
	_, err := credentials.refreshTokenWithRetries(context.Background(), http.DefaultClient)

	if err == nil {
		t.Fatal("Expected error after retries exhausted")
	}

	mu.Lock()
	final := callCount
	mu.Unlock()
	// 1 initial + 2 retries = 3 total
	if final != 3 {
		t.Errorf("Expected 3 calls (1 initial + 2 retries), got %d", final)
	}
}

func TestRefreshTokenWithRetries_disabled(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}))
	defer server.Close()

	credentials := NewOAuth2ClientCredentials("client", "secret", server.URL, WithMaxRetries(0))
	_, err := credentials.refreshTokenWithRetries(context.Background(), http.DefaultClient)

	if err == nil {
		t.Fatal("Expected error but got none")
	}
	if callCount != 1 {
		t.Errorf("Expected exactly 1 call with retries disabled, got %d", callCount)
	}
}

func TestRefreshTokenWithRetries_context_cancellation(t *testing.T) {
	callCount := 0
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())

	// Use a long delay so context cancellation fires during the wait
	credentials := NewOAuth2ClientCredentials("client", "secret", server.URL,
		WithMaxRetries(5), WithBaseDelay(10.0), WithMaxDelay(10.0), WithJitter(JitterNone))

	done := make(chan error, 1)
	go func() {
		_, err := credentials.refreshTokenWithRetries(ctx, http.DefaultClient)
		done <- err
	}()

	// Wait for first attempt to complete, then cancel
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Expected context.Canceled error, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout: context cancellation did not abort retry loop")
	}

	mu.Lock()
	final := callCount
	mu.Unlock()
	if final != 1 {
		t.Errorf("Expected 1 call before context cancelled, got %d", final)
	}
}

// countingTransport is an http.RoundTripper that counts calls and always
// returns the configured error. Used to verify retry attempt counts for
// transport-level failures like connection refused.
type countingTransport struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (ct *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	ct.mu.Lock()
	ct.calls++
	ct.mu.Unlock()
	return nil, ct.err
}

func TestRefreshTokenWithRetries_connection_refused(t *testing.T) {
	transport := &countingTransport{
		err: &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("connection refused")},
	}

	credentials := NewOAuth2ClientCredentials("client", "secret", "http://127.0.0.1:1/token",
		WithMaxRetries(2), WithBaseDelay(0.01), WithMaxDelay(0.02), WithJitter(JitterNone))

	_, err := credentials.refreshTokenWithRetries(context.Background(), &http.Client{Transport: transport})
	if err == nil {
		t.Fatal("Expected error for connection refused")
	}

	var netErr net.Error
	if !errors.As(err, &netErr) {
		t.Errorf("Expected net.Error, got %T: %v", err, err)
	}

	// 1 initial + 2 retries = 3 total attempts
	transport.mu.Lock()
	attempts := transport.calls
	transport.mu.Unlock()
	if attempts != 3 {
		t.Errorf("Expected 3 attempts (1 initial + 2 retries), got %d", attempts)
	}
}

func TestGetToken_retries_500_then_succeeds(t *testing.T) {
	callCount := 0
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		current := callCount
		mu.Unlock()

		if current == 1 {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "retry-success",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}); err != nil {
			t.Errorf("Failed to encode test response: %v", err)
		}
	}))
	defer server.Close()

	credentials := NewOAuth2ClientCredentials("client", "secret", server.URL,
		WithMaxRetries(3), WithBaseDelay(0.01), WithMaxDelay(0.02), WithJitter(JitterNone))

	resp, err := credentials.GetToken(context.Background(), GetTokenOptions{})
	if err != nil {
		t.Fatalf("Expected successful token after retry, got error: %v", err)
	}
	if resp.AccessToken != "retry-success" {
		t.Errorf("Expected 'retry-success', got %q", resp.AccessToken)
	}

	mu.Lock()
	final := callCount
	mu.Unlock()
	if final != 2 {
		t.Errorf("Expected 2 calls (1 failure + 1 success), got %d", final)
	}
}

func TestGetToken_concurrent_with_retries(t *testing.T) {
	callCount := 0
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		current := callCount
		mu.Unlock()

		// First attempt fails, second succeeds (retry within the single
		// goroutine that wins the lock)
		if current == 1 {
			time.Sleep(50 * time.Millisecond)
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "coalesced-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}); err != nil {
			t.Errorf("Failed to encode test response: %v", err)
		}
	}))
	defer server.Close()

	credentials := NewOAuth2ClientCredentials("client", "secret", server.URL,
		WithMaxRetries(3), WithBaseDelay(0.01), WithMaxDelay(0.02), WithJitter(JitterNone))

	const numGoroutines = 10
	results := make(chan RefreshTokenResponse, numGoroutines)
	errs := make(chan error, numGoroutines)

	var ready sync.WaitGroup
	ready.Add(numGoroutines)
	gate := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		go func() {
			ready.Done()
			<-gate
			token, err := credentials.GetToken(context.TODO(), GetTokenOptions{})
			if err != nil {
				errs <- err
			} else {
				results <- token
			}
		}()
	}

	ready.Wait()
	close(gate)

	var tokens []RefreshTokenResponse
	for i := 0; i < numGoroutines; i++ {
		select {
		case token := <-results:
			tokens = append(tokens, token)
		case err := <-errs:
			t.Errorf("Unexpected error: %v", err)
		case <-time.After(10 * time.Second):
			t.Fatal("Timeout")
		}
	}

	if len(tokens) != numGoroutines {
		t.Errorf("Expected %d tokens, got %d", numGoroutines, len(tokens))
	}

	for i, token := range tokens {
		if token.AccessToken != "coalesced-token" {
			t.Errorf("Token %d: expected 'coalesced-token', got '%s'", i, token.AccessToken)
		}
	}

	// Only one goroutine should perform the retry sequence
	mu.Lock()
	final := callCount
	mu.Unlock()
	if final != 2 {
		t.Errorf("Expected 2 calls (1 failure + 1 retry), got %d (thundering herd?)", final)
	}
}

func TestRefreshTokenWithRetries_preserves_nil_transport(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "nil-transport-ok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}); err != nil {
			t.Errorf("Failed to encode test response: %v", err)
		}
	}))
	defer server.Close()

	credentials := NewOAuth2ClientCredentials("client", "secret", server.URL)
	// Pass client with nil Transport (should use http.DefaultTransport)
	resp, err := credentials.refreshTokenWithRetries(context.Background(), &http.Client{})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.AccessToken != "nil-transport-ok" {
		t.Errorf("Expected 'nil-transport-ok', got %q", resp.AccessToken)
	}
}

func TestRefreshTokenWithRetries_retry_on_eof(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		current := callCount
		mu.Unlock()

		if current == 1 {
			// Hijack the connection and close it immediately without
			// sending response headers, causing the client to receive EOF.
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Error("ResponseWriter does not support hijacking")
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				t.Errorf("Hijack failed: %v", err)
				return
			}
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("conn.Close failed: %v", closeErr)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "after-eof",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}); err != nil {
			t.Errorf("Failed to encode test response: %v", err)
		}
	}))
	defer server.Close()

	credentials := NewOAuth2ClientCredentials("client", "secret", server.URL,
		WithMaxRetries(3), WithBaseDelay(0.01), WithMaxDelay(0.02), WithJitter(JitterNone))

	// Disable keep-alives so the second request opens a fresh connection
	// instead of reusing the closed one.
	httpClient := &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	resp, err := credentials.refreshTokenWithRetries(context.Background(), httpClient)

	if err != nil {
		t.Fatalf("Expected successful token after EOF retry, got: %v", err)
	}
	if resp.AccessToken != "after-eof" {
		t.Errorf("Expected 'after-eof', got %q", resp.AccessToken)
	}

	mu.Lock()
	final := callCount
	mu.Unlock()
	if final != 2 {
		t.Errorf("Expected 2 calls (1 EOF + 1 success), got %d", final)
	}
}
