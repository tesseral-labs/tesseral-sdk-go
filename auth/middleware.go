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
type Option struct {
	PublishableKey      string
	ConfigAPIHostname   string
	HttpClient          *http.Client
	JwksRefreshInterval time.Duration
	APIKeysEnabled      *bool
	TesseralClient      *client.Client
}

// WithPublishableKey sets the publishable key for [RequireAuth]. This is
// always required.
var WithPublishableKey = accesstoken.WithPublishableKey

// WithConfigAPIHostname sets the config API hostname for [RequireAuth].
//
// You can typically ignore this option. It is useful for those who self-host
// Tesseral. The default is to use "config.tesseral.com".
var WithConfigAPIHostname = accesstoken.WithConfigAPIHostname

// WithHTTPClient sets the HTTP client used internally by [RequireAuth].
//
// The default is to use [http.DefaultClient].
var WithHTTPClient = accesstoken.WithHTTPClient

// WithJWKSRefreshInterval sets the JWKS refresh interval for [RequireAuth].
//
// [RequireAuth] keeps a cache of public keys used to sign access tokens. This
// option controls how often that cache is updated. The default is to refresh
// JWKS every 60 minutes.
var WithJWKSRefreshInterval = accesstoken.WithJWKSRefreshInterval

// RequireAuth blocks all request to h unless they are authenticated.
//
// opts must contain [WithPublishableKey]. All other options are optional.
//
// If a request is inauthentic, h will not be called. Instead, the server
// serves a [http.StatusUnauthorized] error.
//
// If a request is authentic, h will be called with a request whose context
// works with [OrganizationID], [AccessTokenClaims], and [Credentials].
func RequireAuth(h http.Handler, opts Option) http.Handler {
	if opts.APIKeysEnabled != nil && *opts.APIKeysEnabled && opts.TesseralClient == nil && os.Getenv("TESSERAL_BACKEND_API_KEY") == "" {
		panic("RequireAuth: tesseral client is required when API keys are enabled")
	}

	authn := accesstoken.NewAuthenticator(
		WithConfigAPIHostname(opts.ConfigAPIHostname),
		WithPublishableKey(opts.PublishableKey),
		WithHTTPClient(opts.HttpClient),
		WithJWKSRefreshInterval(opts.JwksRefreshInterval),
	)

	tesseralClient := opts.TesseralClient
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

		if IsJWTFormat(credential) {
			accessTokenClaims, err := authn.AuthenticateAccessToken(ctx, credential)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			ctx = newAccessTokenAuthContext(ctx, credential, accessTokenClaims)
			h.ServeHTTP(w, r.WithContext(ctx))
		} else if opts.APIKeysEnabled != nil && *opts.APIKeysEnabled && IsAPIKeyFormat(credential) {
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
