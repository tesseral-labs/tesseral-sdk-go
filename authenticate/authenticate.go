// Package authenticate provides utilities for extracting authenticated
// information from access tokens.
package authenticate

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

// Authenticator extracts authenticated information from access tokens.
//
// Instances of Authenticator keep an internal cache of public keys. To take
// advantage of that cache, you should create a single instance of
// [Authenticator], and share it between requests.
//
// Instances of Authenticator are safe for concurrent use.
type Authenticator struct {
	publishableKey      string
	configAPIHostname   string
	httpClient          *http.Client
	jwksRefreshInterval time.Duration

	jwksMu          sync.RWMutex // guards jwks and jwksNextRefresh
	jwks            map[string]ecdsa.PublicKey
	jwksNextRefresh time.Time
}

// AuthenticatorOption defines a function that applies a configuration to an
// [Authenticator]. Used for [NewAuthenticator].
type AuthenticatorOption func(*Authenticator)

// WithPublishableKey sets the publishable key for the [Authenticator]. This is
// always required.
func WithPublishableKey(key string) AuthenticatorOption {
	return func(a *Authenticator) {
		a.publishableKey = key
	}
}

// WithConfigAPIHostname sets the config API hostname for the Authenticator.
//
// You can typically ignore this option. It is useful for those who self-host
// Tesseral. The default is to use "config.tesseral.com".
func WithConfigAPIHostname(hostname string) AuthenticatorOption {
	return func(a *Authenticator) {
		a.configAPIHostname = hostname
	}
}

// WithHttpClient sets the HTTP client for the [Authenticator].
//
// The default is to use [http.DefaultClient].
func WithHttpClient(client *http.Client) AuthenticatorOption {
	return func(a *Authenticator) {
		a.httpClient = client
	}
}

// WithJWKSRefreshInterval sets the JWKS refresh interval for the
// [Authenticator].
//
// An [Authenticator] keeps a cache of public keys used to sign access tokens.
// This option controls how often that cache is updated. The default is to
// refresh JWKS every 60 minutes.
func WithJWKSRefreshInterval(interval time.Duration) AuthenticatorOption {
	return func(a *Authenticator) {
		a.jwksRefreshInterval = interval
	}
}

// NewAuthenticator creates a new Authenticator with the provided options.
func NewAuthenticator(opts ...AuthenticatorOption) (*Authenticator, error) {
	authenticator := &Authenticator{
		configAPIHostname:   "config.tesseral.com",
		httpClient:          http.DefaultClient,
		jwksRefreshInterval: 1 * time.Hour, // Default refresh interval
		jwks:                make(map[string]ecdsa.PublicKey),
	}
	for _, opt := range opts {
		opt(authenticator)
	}

	if authenticator.publishableKey == "" {
		return nil, fmt.Errorf("NewAuthenticator: publishable key is required")
	}

	return authenticator, nil
}

// ErrInvalidAccessToken indicates that an access token is invalid.
var ErrInvalidAccessToken = fmt.Errorf("invalid access token")

// AuthenticateAccessToken authenticate and returns the
// [tesseral.AccessTokenClaims] inside accessToken.
//
// If the access token is invalid for any reason, AuthenticateAccessTokens
// returns nil, [ErrInvalidAccessToken].
//
// AuthenticateAccessToken is safe for concurrent use.
func (a *Authenticator) AuthenticateAccessToken(ctx context.Context, accessToken string) (*tesseral.AccessTokenClaims, error) {
	jwks, err := a.getJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("get jwks: %w", err)
	}
	return authenticateAccessToken(jwks, time.Now(), accessToken)
}

func (a *Authenticator) getJWKS(ctx context.Context) (map[string]ecdsa.PublicKey, error) {
	// common path: jwks is fresh
	a.jwksMu.RLock()
	if a.jwksNextRefresh.After(time.Now()) {
		defer a.jwksMu.RUnlock()
		return a.jwks, nil
	}
	a.jwksMu.RUnlock()

	// need to (re)fetch
	a.jwksMu.Lock()
	defer a.jwksMu.Unlock()

	// now that we have acquired write-lock, confirm another goroutine hasn't
	// already done this work
	if a.jwksNextRefresh.After(time.Now()) {
		return a.jwks, nil
	}

	// we are the winning goroutine to do the work
	jwks, err := a.fetchJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}

	a.jwks = jwks
	a.jwksNextRefresh = time.Now().Add(a.jwksRefreshInterval)
	return a.jwks, nil
}

func (a *Authenticator) fetchJWKS(ctx context.Context) (map[string]ecdsa.PublicKey, error) {
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

	jwks, err := parseJWKS(body)
	if err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}

	return jwks, nil
}

func parseJWKS(jwksData []byte) (map[string]ecdsa.PublicKey, error) {
	var jwksResponse struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(jwksData, &jwksResponse); err != nil {
		return nil, fmt.Errorf("unmarshal response body: %w", err)
	}

	jwks := make(map[string]ecdsa.PublicKey)
	for _, key := range jwksResponse.Keys {
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

	return jwks, nil
}

type jwk struct {
	KID string `json:"kid"`
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func authenticateAccessToken(jwks map[string]ecdsa.PublicKey, now time.Time, accessToken string) (*tesseral.AccessTokenClaims, error) {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidAccessToken
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidAccessToken
	}
	var header struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrInvalidAccessToken
	}

	pub, ok := jwks[header.KID]
	if !ok {
		return nil, ErrInvalidAccessToken
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidAccessToken
	}

	var signedPart []byte
	signedPart = append(signedPart, parts[0]...)
	signedPart = append(signedPart, '.')
	signedPart = append(signedPart, parts[1]...)

	hash := sha256.Sum256(signedPart)

	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidAccessToken
	}

	if len(signatureBytes) != 64 {
		return nil, ErrInvalidAccessToken
	}

	var r, s big.Int
	r.SetBytes(signatureBytes[:32])
	s.SetBytes(signatureBytes[32:])

	if !ecdsa.Verify(&pub, hash[:], &r, &s) {
		return nil, ErrInvalidAccessToken
	}

	var claims tesseral.AccessTokenClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, ErrInvalidAccessToken
	}

	nowUnix := float64(now.Unix())
	if nowUnix < *claims.Nbf || nowUnix > *claims.Exp {
		return nil, ErrInvalidAccessToken
	}

	return &claims, nil
}
