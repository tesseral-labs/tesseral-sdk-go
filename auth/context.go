package auth

import (
	"context"
	"fmt"

	"github.com/tesseral-labs/tesseral-sdk-go"
)

var errNotAnAccessToken = fmt.Errorf("not an access token")

type ctxKey struct{}

type accessTokenDetails struct {
	accessToken string
	claims      *tesseral.AccessTokenClaims
}

type apiKeyDetails struct {
	apiKeySecretToken          string
	authenticateAPIKeyResponse *tesseral.AuthenticateAPIKeyResponse
}

type ctxValue struct {
	accessTokenDetails *accessTokenDetails
	apiKeyDetails      *apiKeyDetails
}

func newAccessTokenAuthContext(ctx context.Context, accessToken string, claims *tesseral.AccessTokenClaims) context.Context {
	return context.WithValue(ctx, ctxKey{}, &ctxValue{
		accessTokenDetails: &accessTokenDetails{
			accessToken: accessToken,
			claims:      claims,
		},
	})
}

func newAPIKeyAuthContext(ctx context.Context, apiKeySecretToken string, response *tesseral.AuthenticateAPIKeyResponse) context.Context {
	return context.WithValue(ctx, ctxKey{}, &ctxValue{
		apiKeyDetails: &apiKeyDetails{
			apiKeySecretToken:          apiKeySecretToken,
			authenticateAPIKeyResponse: response,
		},
	})
}

func mustAuthContext(ctx context.Context, name string) *ctxValue {
	if v, ok := ctx.Value(ctxKey{}).(*ctxValue); ok {
		return v
	}
	panic(fmt.Sprintf("called auth.%s(ctx) but ctx does not carry auth information; did you forget to use auth.RequireAuth?", name))
}

// CredentialsType returns the type of credentials used to authenticate the
// request.
//
// For accessToken-based authentication, this will be "access_token". For
// apiKey-based authentication, this will be "api_key".
func CredentialsType(ctx context.Context) string {
	v := mustAuthContext(ctx, "CredentialsType")

	if v.apiKeyDetails != nil {
		return "api_key"
	}
	if v.accessTokenDetails != nil {
		return "access_token"
	}
	panic("unreachable")
}

// OrganizationID returns the ID of the organization the requester belongs to.
//
// Panics if the provided ctx isn't downstream of [RequireAuth].
func OrganizationID(ctx context.Context) string {
	v := mustAuthContext(ctx, "OrganizationID")

	if v.apiKeyDetails != nil {
		return *v.apiKeyDetails.authenticateAPIKeyResponse.OrganizationID
	}
	if v.accessTokenDetails != nil {
		return v.accessTokenDetails.claims.Organization.ID
	}

	panic("unreachable")
}

// AccessTokenClaims returns the claims inside the request's access token, if
// any.
//
// Future versions of this package may add support for other kinds of
// authentication than access tokens, in which case AccessTokenClaims may return
// an error.
//
// Panics if the provided ctx isn't downstream of [RequireAuth].
func AccessTokenClaims(ctx context.Context) (*tesseral.AccessTokenClaims, error) {
	v := mustAuthContext(ctx, "AccessTokenClaims")

	if v.accessTokenDetails != nil {
		return v.accessTokenDetails.claims, nil
	}

	return nil, errNotAnAccessToken
}

// Credentials returns the request's original credentials.
//
// Panics if the provided ctx isn't downstream of [RequireAuth].
func Credentials(ctx context.Context) string {
	v := mustAuthContext(ctx, "Credentials")
	if v.apiKeyDetails != nil {
		return v.apiKeyDetails.apiKeySecretToken
	}
	if v.accessTokenDetails != nil {
		return v.accessTokenDetails.accessToken
	}

	panic("unreachable")
}

// HasPermission returns whether the requester has permission to carry out the
// given action.
func HasPermission(ctx context.Context, action string) bool {
	var actions []string

	v := mustAuthContext(ctx, "HasPermission")

	if v.apiKeyDetails != nil && v.apiKeyDetails.authenticateAPIKeyResponse.Actions != nil {
		actions = v.apiKeyDetails.authenticateAPIKeyResponse.Actions
	} else if v.accessTokenDetails != nil && v.accessTokenDetails.claims.Actions != nil {
		actions = v.accessTokenDetails.claims.Actions
	}

	for _, a := range actions {
		if a == action {
			return true
		}
	}

	return false
}
