package auth

import (
	"fmt"
	"net/http"
	"strings"
)

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
	authn := newAuthenticator(opts...)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// call updateConfigData to populate authn.projectID
		if err := authn.updateConfigData(ctx); err != nil {
			panic(fmt.Errorf("fetch tesseral config: %w", err))
		}

		accessToken := extractAccessToken(authn.projectID, r)
		accessTokenClaims, err := authn.authenticateAccessToken(ctx, accessToken)
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
