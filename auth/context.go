package auth

import (
	"context"
	"fmt"

	"github.com/tesseral-labs/tesseral-sdk-go"
)

type ctxKey struct{}

type ctxValue struct {
	accessToken string
	claims      *tesseral.AccessTokenClaims
}

func newAuthContext(ctx context.Context, accessToken string, claims *tesseral.AccessTokenClaims) context.Context {
	return context.WithValue(ctx, ctxKey{}, &ctxValue{accessToken: accessToken, claims: claims})
}

func mustAuthContext(ctx context.Context, name string) *ctxValue {
	if v, ok := ctx.Value(ctxKey{}).(*ctxValue); ok {
		return v
	}
	panic(fmt.Sprintf("called auth.%s(ctx) but ctx does not carry auth information; did you forget to use auth.RequireAuth?", name))
}

// OrganizationID returns the ID of the organization the requester belongs to.
//
// Panics if the provided ctx isn't downstream of [RequireAuth].
func OrganizationID(ctx context.Context) string {
	return *mustAuthContext(ctx, "OrganizationID").claims.Organization.ID
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
	return mustAuthContext(ctx, "AccessTokenClaims").claims, nil
}

// Credentials returns the request's original credentials.
//
// Panics if the provided ctx isn't downstream of [RequireAuth].
func Credentials(ctx context.Context) string {
	return mustAuthContext(ctx, "Token").accessToken
}
