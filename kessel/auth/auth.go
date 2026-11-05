package auth

import (
	"context"
	"errors"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client"
)

const expirationWindow = 300  // 5 minutes in second
const defaultExpiresIn = 3600 // 1 hour in seconds

const (
	// JitterFull applies uniform random jitter in [0, delay).
	JitterFull = "full"
	// JitterNone disables jitter; the exact computed delay is used.
	JitterNone = "none"
)

type OIDCDiscoveryMetadata struct {
	TokenEndpoint string
}

type RefreshTokenResponse struct {
	AccessToken string
	ExpiresAt   time.Time
}

// retryConfig holds the resolved retry configuration for OIDC token
// endpoint requests. Construct via [RetryOption] functional options
// passed to [NewOAuth2ClientCredentials].
type retryConfig struct {
	maxRetries int
	baseDelay  float64
	maxDelay   float64
	jitter     string
}

// defaultRetryConfig returns the default retry configuration:
// 3 retries, 0.5s base delay, 2.0s max delay, full jitter.
func defaultRetryConfig() retryConfig {
	return retryConfig{
		maxRetries: 3,
		baseDelay:  0.5,
		maxDelay:   2.0,
		jitter:     JitterFull,
	}
}

// RetryOption configures retry behavior for OIDC token endpoint requests.
// Pass one or more RetryOption values to [NewOAuth2ClientCredentials] to
// customize retry behavior. Omitting all options uses the defaults:
// 3 retries, 0.5s base delay, 2.0s max delay, full jitter.
type RetryOption func(*retryConfig)

// WithMaxRetries sets the maximum number of retries after the initial
// request. Set to 0 to disable retries. When omitted, the default (3)
// is used — unlike a struct field, omitting this option never silently
// disables retries.
func WithMaxRetries(n int) RetryOption {
	return func(c *retryConfig) {
		c.maxRetries = n
	}
}

// WithBaseDelay sets the initial exponential backoff delay in seconds
// (default: 0.5).
func WithBaseDelay(seconds float64) RetryOption {
	return func(c *retryConfig) {
		if seconds > 0 {
			c.baseDelay = seconds
		}
	}
}

// WithMaxDelay sets the maximum backoff delay cap in seconds
// (default: 2.0).
func WithMaxDelay(seconds float64) RetryOption {
	return func(c *retryConfig) {
		if seconds > 0 {
			c.maxDelay = seconds
		}
	}
}

// WithJitter sets the jitter strategy: [JitterFull] (default) or
// [JitterNone].
func WithJitter(mode string) RetryOption {
	return func(c *retryConfig) {
		if mode != "" {
			c.jitter = mode
		}
	}
}

type OAuth2ClientCredentials struct {
	clientId      string
	clientSecret  string
	tokenEndpoint string
	cachedToken   RefreshTokenResponse
	tokenMutex    sync.RWMutex
	generation    uint64
	retry         retryConfig
}

type FetchOIDCDiscoveryOptions struct {
	// Optionally specify an http.Client or use http.DefaultClient
	HttpClient *http.Client
}

type GetTokenOptions struct {
	// Whether the token should be refreshed regardless if it is expired or not
	ForceRefresh bool
	// Optionally specify an http.Client or use http.DefaultClient
	HttpClient *http.Client
}

type oauth2TokenEndpointCaller struct {
	tokenEndpoint string
	httpClient    *http.Client
}

type requestToken struct {
	ClientID     string `schema:"client_id,omitempty"`
	ClientSecret string `schema:"client_secret,omitempty"`
	GrantType    string `schema:"grant_type"`
}

// statusCapturingTransport wraps an http.RoundTripper to record the
// HTTP status code of the most recent response. This allows retry
// logic to classify errors by status code even when the OIDC library
// converts the response into an opaque error.
type statusCapturingTransport struct {
	base       http.RoundTripper
	lastStatus int
}

func (t *statusCapturingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if resp != nil {
		t.lastStatus = resp.StatusCode
	} else {
		t.lastStatus = 0
	}
	return resp, err
}

// NewOAuth2ClientCredentials creates an OAuth2 client-credentials provider.
// If no [RetryOption] values are passed, the default retry policy is used
// (3 retries, exponential backoff with full jitter). Partial customization
// retains defaults for unset fields — for example, passing only
// [WithJitter](JitterNone) keeps the default retry count of 3. Pass
// [WithMaxRetries](0) to disable retries entirely.
func NewOAuth2ClientCredentials(clientId string, clientSecret string, tokenEndpoint string, opts ...RetryOption) OAuth2ClientCredentials {
	retry := defaultRetryConfig()
	for _, opt := range opts {
		opt(&retry)
	}
	return OAuth2ClientCredentials{
		clientId:      clientId,
		clientSecret:  clientSecret,
		tokenEndpoint: tokenEndpoint,
		cachedToken:   RefreshTokenResponse{},
		tokenMutex:    sync.RWMutex{},
		generation:    0,
		retry:         retry,
	}
}

func FetchOIDCDiscovery(ctx context.Context, issuerUrl string, options FetchOIDCDiscoveryOptions) (OIDCDiscoveryMetadata, error) {
	httpClient := options.HttpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	discoveryConfig, err := client.Discover(ctx, issuerUrl, httpClient)
	if err != nil {
		return OIDCDiscoveryMetadata{}, err
	}

	return OIDCDiscoveryMetadata{TokenEndpoint: discoveryConfig.TokenEndpoint}, nil
}

func (o *OAuth2ClientCredentials) GetToken(ctx context.Context, options GetTokenOptions) (RefreshTokenResponse, error) {
	httpClient := options.HttpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	// Snapshot generation before any lock so all concurrent callers that
	// decide to refresh see the same value, regardless of lock ordering.
	generation := atomic.LoadUint64(&o.generation)

	o.tokenMutex.RLock()
	if !options.ForceRefresh && o.isTokenValid() {
		token := o.cachedToken
		o.tokenMutex.RUnlock()
		return token, nil
	}
	o.tokenMutex.RUnlock()

	o.tokenMutex.Lock()
	defer o.tokenMutex.Unlock()

	if atomic.LoadUint64(&o.generation) != generation && o.isTokenValid() {
		return o.cachedToken, nil
	}

	var err error
	o.cachedToken, err = o.refreshTokenWithRetries(ctx, httpClient)
	if err != nil {
		return RefreshTokenResponse{}, err
	}
	atomic.AddUint64(&o.generation, 1)

	return o.cachedToken, nil
}

func (o *OAuth2ClientCredentials) refreshTokenWithRetries(ctx context.Context, httpClient *http.Client) (RefreshTokenResponse, error) {
	maxRetries := o.retry.maxRetries
	if maxRetries <= 0 {
		return o.refreshToken(ctx, httpClient)
	}

	transport := httpClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	capture := &statusCapturingTransport{base: transport}
	clientCopy := *httpClient
	clientCopy.Transport = capture
	retryClient := &clientCopy

	var lastErr error
	for attempt := range maxRetries + 1 {
		if attempt > 0 {
			delay := o.retryDelay(attempt - 1)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return RefreshTokenResponse{}, ctx.Err()
			}
		}

		capture.lastStatus = 0
		resp, err := o.refreshToken(ctx, retryClient)
		if err == nil {
			return resp, nil
		}

		lastErr = err

		if !isRetryableError(err, capture.lastStatus) {
			return RefreshTokenResponse{}, err
		}
	}

	return RefreshTokenResponse{}, lastErr
}

func (o *OAuth2ClientCredentials) refreshToken(ctx context.Context, httpClient *http.Client) (RefreshTokenResponse, error) {
	request := requestToken{
		ClientID:     o.clientId,
		ClientSecret: o.clientSecret,
		GrantType:    "client_credentials",
	}

	tokenEndpointCaller := oauth2TokenEndpointCaller{
		tokenEndpoint: o.tokenEndpoint,
		httpClient:    httpClient,
	}

	token, err := client.CallTokenEndpoint(ctx, request, tokenEndpointCaller)

	if err != nil {
		return RefreshTokenResponse{}, err
	}

	now := time.Now()
	expiresAt := token.Expiry

	// zitadel populates Expiry from expires_in and leaves ExpiresIn at zero.
	// Fall back to ExpiresIn, then the default, only when Expiry is missing
	// or already past.
	if !expiresAt.After(now) {
		expiresIn := token.ExpiresIn
		if expiresIn <= 0 {
			expiresIn = defaultExpiresIn
		}
		expiresAt = now.Add(time.Duration(expiresIn) * time.Second)
	}

	return RefreshTokenResponse{
		AccessToken: token.AccessToken,
		ExpiresAt:   expiresAt,
	}, nil
}

func (o *OAuth2ClientCredentials) isTokenValid() bool {
	if o.cachedToken.AccessToken == "" {
		return false
	}

	return time.Now().Add(time.Duration(expirationWindow) * time.Second).Before(o.cachedToken.ExpiresAt)
}

// retryDelay computes the backoff delay for the given retry index using
// bounded exponential backoff. With full jitter, the delay is a random
// value in [0, cap). With no jitter, the exact cap is used.
func (o *OAuth2ClientCredentials) retryDelay(retryIndex int) time.Duration {
	computed := min(o.retry.maxDelay, o.retry.baseDelay*math.Pow(2, float64(retryIndex)))
	if o.retry.jitter == JitterNone {
		return time.Duration(computed * float64(time.Second))
	}
	return time.Duration(rand.Float64() * computed * float64(time.Second))
}

// isRetryableError returns true for transient errors that should be retried:
// network/connection errors, timeouts, EOF (connection closed before response
// headers), HTTP 429, and HTTP 5xx responses. Permanent errors wrapped in
// *url.Error (TLS failures, unsupported schemes, context cancellation) are
// not retried.
func isRetryableError(err error, httpStatus int) bool {
	// *url.Error wraps all http.Client transport errors and satisfies
	// net.Error, so inspect the underlying cause first to avoid retrying
	// permanent failures (e.g. TLS certificate errors, unsupported schemes).
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return true
		}
		// EOF and unexpected EOF indicate the server closed the connection
		// before sending response headers — a transient transport failure
		// that is safe to retry. This matches the retry behavior of the
		// Python and Ruby SDKs.
		if errors.Is(urlErr.Err, io.EOF) || errors.Is(urlErr.Err, io.ErrUnexpectedEOF) {
			return true
		}
		var inner net.Error
		return errors.As(urlErr.Err, &inner)
	}

	// Network and timeout errors (connection refused, DNS failure, etc.)
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	// HTTP 429 Too Many Requests or 5xx server errors
	if httpStatus == http.StatusTooManyRequests || httpStatus >= 500 {
		return true
	}

	return false
}

func (o oauth2TokenEndpointCaller) TokenEndpoint() string {
	return o.tokenEndpoint
}

func (o oauth2TokenEndpointCaller) HttpClient() *http.Client {
	return o.httpClient
}
