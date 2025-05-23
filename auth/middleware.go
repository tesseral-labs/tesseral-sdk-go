package auth

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tesseral-labs/tesseral-sdk-go"
	"github.com/tesseral-labs/tesseral-sdk-go/accesstoken"
	"github.com/tesseral-labs/tesseral-sdk-go/client"
)

// Option is an option for [RequireAuth].
type option struct {
	PublishableKey      string
	ConfigAPIHostname   string
	HttpClient          *http.Client
	JwksRefreshInterval time.Duration
	APIKeysEnabled      *bool
	TesseralClient      *client.Client
}

type Option func(*option)

// WithAPIKeysEnabled sets whether API keys are enabled for [RequireAuth].
// This is optional. If not set, API keys are disabled.
// If set to true, the [RequireAuth] middleware will authenticate requests
// using API keys. If set to false, the middleware will only authenticate
// requests using access tokens.
// If API keys are enabled, you must provide a [TesseralClient] to
// [RequireAuth] or have the `TESSERAL_BACKEND_API_KEY` environment variable
// set.
// The middleware will use the default [client.NewClient] if one is not
// provided.
func WithAPIKeysEnabled(enabled bool) Option {
	return func(o *option) {
		o.APIKeysEnabled = &enabled
	}
}

// WithTesseralClient sets the Tesseral client for [RequireAuth].
// This is optional. If not set, the middleware will use the default
// [client.NewClient].
// If API keys are enabled, you must provide a [TesseralClient] to
// [RequireAuth] or have the `TESSERAL_BACKEND_API_KEY` environment variable
// set.
// The middleware will use the default [client.NewClient] if one is not
// provided.
func WithTesseralClient(client *client.Client) Option {
	return func(o *option) {
		o.TesseralClient = client
	}
}

// WithPublishableKey sets the publishable key for [RequireAuth]. This is
// always required.
func WithPublishableKey(publishableKey string) Option {
	return func(o *option) {
		o.PublishableKey = publishableKey
	}
}

// WithConfigAPIHostname sets the config API hostname for [RequireAuth].
//
// You can typically ignore this option. It is useful for those who self-host
// Tesseral. The default is to use "config.tesseral.com".
func WithConfigAPIHostname(hostname string) Option {
	return func(o *option) {
		o.ConfigAPIHostname = hostname
	}
}

// WithHTTPClient sets the HTTP client used internally by [RequireAuth].
//
// The default is to use [http.DefaultClient].
func WithHTTPClient(client *http.Client) Option {
	return func(o *option) {
		o.HttpClient = client
	}
}

// WithJWKSRefreshInterval sets the JWKS refresh interval for [RequireAuth].
//
// [RequireAuth] keeps a cache of public keys used to sign access tokens. This
// option controls how often that cache is updated. The default is to refresh
// JWKS every 60 minutes.
func WithJWKSRefreshInterval(interval time.Duration) Option {
	return func(o *option) {
		o.JwksRefreshInterval = interval
	}
}

// RequireAuth blocks all request to h unless they are authenticated.
//
// opts must contain [WithPublishableKey]. All other options are optional.
//
// If a request is inauthentic, h will not be called. Instead, the server
// serves a [http.StatusUnauthorized] error.
//
// If a request is authentic, h will be called with a request whose context
// works with [OrganizationID], [AccessTokenClaims], and [Credentials].
func RequireAuth(h http.Handler, opts ...Option) http.Handler {
	cfg := &option{}

	for _, opt := range opts {
		opt(cfg) // mutate cfg using each Option
	}

	if cfg.APIKeysEnabled != nil && *cfg.APIKeysEnabled && cfg.TesseralClient == nil && os.Getenv("TESSERAL_BACKEND_API_KEY") == "" {
		panic("RequireAuth: tesseral client is required when API keys are enabled")
	}

	authnOpts := []accesstoken.Option{
		accesstoken.WithPublishableKey(cfg.PublishableKey),
	}

	if cfg.ConfigAPIHostname != "" {
		authnOpts = append(authnOpts, accesstoken.WithConfigAPIHostname(cfg.ConfigAPIHostname))
	}

	if cfg.HttpClient != nil {
		authnOpts = append(authnOpts, accesstoken.WithHTTPClient(cfg.HttpClient))
	}

	if cfg.JwksRefreshInterval != 0 {
		authnOpts = append(authnOpts, accesstoken.WithJWKSRefreshInterval(cfg.JwksRefreshInterval))
	}

	authn := accesstoken.NewAuthenticator(authnOpts...)

	tesseralClient := cfg.TesseralClient
	if tesseralClient == nil {
		tesseralClient = client.NewClient()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		projectID, err := authn.ProjectID(ctx)
		if err != nil {
			panic(fmt.Errorf("RequireAuth: error fetching publishable key configuration: %w", err))
		}

		credential := extractCredential(projectID, r)

		fmt.Println("Credential:", credential)

		if IsJWTFormat(credential) {
			accessTokenClaims, err := authn.AuthenticateAccessToken(ctx, credential)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			ctx = newAccessTokenAuthContext(ctx, credential, accessTokenClaims)
			h.ServeHTTP(w, r.WithContext(ctx))
		} else if cfg.APIKeysEnabled != nil && *cfg.APIKeysEnabled && IsAPIKeyFormat(credential) {
			apiKeyDetails, err := tesseralClient.APIKeys.AuthenticateAPIKey(ctx, &tesseral.AuthenticateAPIKeyRequest{
				SecretToken: &credential,
			})
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			ctx = newAPIKeyAuthContext(ctx, credential, apiKeyDetails)
			h.ServeHTTP(w, r.WithContext(ctx))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
}

func extractCredential(projectID string, r *http.Request) string {
	authorization := r.Header.Get("Authorization")
	if strings.HasPrefix(authorization, "Bearer ") {
		return strings.TrimPrefix(authorization, "Bearer ")
	}

	cookie, _ := r.Cookie(fmt.Sprintf("tesseral_%s_access_token", projectID))
	if cookie != nil {
		return cookie.Value
	}

	return ""
}
