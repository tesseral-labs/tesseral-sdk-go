package accesstoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tesseral-labs/tesseral-sdk-go"
)

type options struct {
	publishableKey      string
	configAPIHostname   string
	httpClient          *http.Client
	jwksRefreshInterval time.Duration
}

// Option is an option for [NewAuthenticator].
type Option func(*options)

// WithPublishableKey sets the publishable key for [NewAuthenticator]. This is
// always required.
func WithPublishableKey(publishableKey string) Option {
	return func(o *options) {
		o.publishableKey = publishableKey
	}
}

// WithConfigAPIHostname sets the config API hostname for [NewAuthenticator].
//
// You can typically ignore this option. It is useful for those who self-host
// Tesseral. The default is to use "config.tesseral.com".
func WithConfigAPIHostname(hostname string) Option {
	return func(o *options) {
		o.configAPIHostname = hostname
	}
}

// WithHTTPClient sets the HTTP client used internally by [NewAuthenticator].
//
// The default is to use [http.DefaultClient].
func WithHTTPClient(client *http.Client) Option {
	return func(o *options) {
		o.httpClient = client
	}
}

// WithJWKSRefreshInterval sets the JWKS refresh interval for [NewAuthenticator].
//
// [Authenticator] keeps a cache of public keys used to sign access tokens. This
// option controls how often that cache is updated. The default is to refresh
// JWKS every 60 minutes.
func WithJWKSRefreshInterval(interval time.Duration) Option {
	return func(o *options) {
		o.jwksRefreshInterval = interval
	}
}

// Authenticator verifies the authenticity of access tokens, and returns the
// claims they encode.
//
// Authenticator is safe for concurrent use and should be re-used across
// requests.
//
// The zero value of Authenticator is not valid. You must construct an
// Authenticator using NewAuthenticator.
type Authenticator struct {
	options
	projectID string

	jwksMu          sync.RWMutex // guards jwks and jwksNextRefresh
	jwks            map[string]ecdsa.PublicKey
	jwksNextRefresh time.Time
}

// NewAuthenticator constructs an Authenticator. You must include
// [WithPublishableKey] in opts, all other options are optional.
func NewAuthenticator(opts ...Option) *Authenticator {
	options := &options{
		configAPIHostname:   "config.tesseral.com",
		httpClient:          http.DefaultClient,
		jwksRefreshInterval: 1 * time.Hour,
	}
	for _, opt := range opts {
		opt(options)
	}

	if options.publishableKey == "" {
		panic(fmt.Errorf("auth.RequireAuth: you must provide an auth.WithPublishableKey() option"))
	}

	return &Authenticator{
		options: *options,
		jwks:    make(map[string]ecdsa.PublicKey),
	}
}

// ProjectID returns the Project ID for this Authenticator.
func (a *Authenticator) ProjectID(ctx context.Context) (string, error) {
	if err := a.updateConfigData(ctx); err != nil {
		return "", fmt.Errorf("update config data: %w", err)
	}
	return a.projectID, nil
}

// AuthenticateAccessToken authenticates an access token and returns the claims
// it contains.
//
// Returns an error if the access token is inauthentic, invalid, or expired.
func (a *Authenticator) AuthenticateAccessToken(ctx context.Context, accessToken string) (*tesseral.AccessTokenClaims, error) {
	if err := a.updateConfigData(ctx); err != nil {
		return nil, fmt.Errorf("update config data: %w", err)
	}
	return authenticateAccessToken(a.jwks, now(), accessToken)
}

// now is a var so we can unit-test timestamps without exposing an unsafe API
var now = time.Now

var errInvalidAccessToken = fmt.Errorf("invalid access token")

func authenticateAccessToken(jwks map[string]ecdsa.PublicKey, now time.Time, accessToken string) (*tesseral.AccessTokenClaims, error) {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return nil, errInvalidAccessToken
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errInvalidAccessToken
	}
	var header struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, errInvalidAccessToken
	}

	pub, ok := jwks[header.KID]
	if !ok {
		return nil, errInvalidAccessToken
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errInvalidAccessToken
	}

	var signedPart []byte
	signedPart = append(signedPart, parts[0]...)
	signedPart = append(signedPart, '.')
	signedPart = append(signedPart, parts[1]...)

	hash := sha256.Sum256(signedPart)

	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errInvalidAccessToken
	}

	if len(signatureBytes) != 64 {
		return nil, errInvalidAccessToken
	}

	var r, s big.Int
	r.SetBytes(signatureBytes[:32])
	s.SetBytes(signatureBytes[32:])

	if !ecdsa.Verify(&pub, hash[:], &r, &s) {
		return nil, errInvalidAccessToken
	}

	var claims tesseral.AccessTokenClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, errInvalidAccessToken
	}

	nowUnix := float64(now.Unix())
	if nowUnix < claims.Nbf || nowUnix > claims.Exp {
		return nil, errInvalidAccessToken
	}

	return &claims, nil
}

type configData struct {
	ProjectID string
	Keys      map[string]ecdsa.PublicKey
}

func (a *Authenticator) updateConfigData(ctx context.Context) error {
	// common path: jwks is fresh
	a.jwksMu.RLock()
	if a.jwksNextRefresh.After(time.Now()) {
		a.jwksMu.RUnlock()
		return nil
	}
	a.jwksMu.RUnlock()

	// need to (re)fetch
	a.jwksMu.Lock()
	defer a.jwksMu.Unlock()

	// now that we have acquired write-lock, confirm another goroutine hasn't
	// already done this work
	if a.jwksNextRefresh.After(time.Now()) {
		return nil
	}

	// we are the winning goroutine to do the work
	config, err := a.fetchConfig(ctx)
	if err != nil {
		return fmt.Errorf("fetch config: %w", err)
	}

	a.projectID = config.ProjectID
	a.jwks = config.Keys
	a.jwksNextRefresh = time.Now().Add(a.jwksRefreshInterval)
	return nil
}

func (a *Authenticator) fetchConfig(ctx context.Context) (*configData, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s/v1/config/%s", a.configAPIHostname, a.publishableKey), nil)
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}

	httpRes, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("do http request: %w", err)
	}
	defer func() { _ = httpRes.Body.Close() }()

	if httpRes.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad response status code: %d", httpRes.StatusCode)
	}

	body, err := io.ReadAll(httpRes.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	config, err := parseConfig(body)
	if err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}

	return config, nil
}

func parseConfig(b []byte) (*configData, error) {
	var configResponse struct {
		ProjectID string `json:"projectID"`
		Keys      []jwk  `json:"keys"`
	}
	if err := json.Unmarshal(b, &configResponse); err != nil {
		return nil, fmt.Errorf("unmarshal response body: %w", err)
	}

	jwks := make(map[string]ecdsa.PublicKey)
	for _, key := range configResponse.Keys {
		if key.KTY != "EC" || key.CRV != "P-256" {
			return nil, fmt.Errorf("unsupported key type/curve: %q/%q", key.KTY, key.CRV)
		}

		xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil {
			return nil, fmt.Errorf("decode x coordinate: %w", err)
		}
		x := new(big.Int).SetBytes(xBytes)

		yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
		if err != nil {
			return nil, fmt.Errorf("decode y coordinate: %w", err)
		}
		y := new(big.Int).SetBytes(yBytes)

		jwks[key.KID] = ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}
	}

	return &configData{
		ProjectID: configResponse.ProjectID,
		Keys:      jwks,
	}, nil
}

type jwk struct {
	KID string `json:"kid"`
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}
