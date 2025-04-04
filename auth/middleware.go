package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/tesseral-labs/tesseral-sdk-go/accesstoken"
)

// Option is an option for [RequireAuth].
type Option = accesstoken.Option

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
func RequireAuth(h http.Handler, opts ...Option) http.Handler {
	authn := accesstoken.NewAuthenticator(opts...)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		projectID, err := authn.ProjectID(ctx)
		if err != nil {
			panic(fmt.Errorf("RequireAuth: error fetching publishable key configuration: %w", err))
		}

		accessToken := extractAccessToken(projectID, r)
		accessTokenClaims, err := authn.AuthenticateAccessToken(ctx, accessToken)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ctx = newAuthContext(ctx, accessToken, accessTokenClaims)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func extractAccessToken(projectID string, r *http.Request) string {
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
