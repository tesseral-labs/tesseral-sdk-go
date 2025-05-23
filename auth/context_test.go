package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tesseral-labs/tesseral-sdk-go"
)

func TestOrganizationID_accesstoken(t *testing.T) {
	ctx := newAccessTokenAuthContext(context.Background(), "", &tesseral.AccessTokenClaims{Organization: &tesseral.AccessTokenOrganization{ID: "foo"}})
	assert.Equal(t, "foo", OrganizationID(ctx))
}

func TestCredentials_accesstoken(t *testing.T) {
	ctx := newAccessTokenAuthContext(context.Background(), "foo", nil)
	assert.Equal(t, "foo", Credentials(ctx))
}

func TestAccessTokenClaims_accesstoken(t *testing.T) {
	want := &tesseral.AccessTokenClaims{Sub: "foo"}
	ctx := newAccessTokenAuthContext(context.Background(), "", want)
	got, err := AccessTokenClaims(ctx)
	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestHasPermission_accesstoken(t *testing.T) {
	ctx := newAccessTokenAuthContext(context.Background(), "", &tesseral.AccessTokenClaims{Actions: []string{"a.b.c", "d.e.f"}})
	assert.True(t, HasPermission(ctx, "a.b.c"))
	assert.True(t, HasPermission(ctx, "d.e.f"))
	assert.False(t, HasPermission(ctx, "x.y.z"))
}

func TestCredentialsType_accesstoken(t *testing.T) {
	ctx := newAccessTokenAuthContext(context.Background(), "", nil)
	assert.Equal(t, "access_token", CredentialsType(ctx))
}

func TestOrganizationID_apikey(t *testing.T) {
	ctx := newAPIKeyAuthContext(context.Background(), "foo", &tesseral.AuthenticateAPIKeyResponse{
		APIKeyID:       tesseral.String("foo"),
		OrganizationID: tesseral.String("foo"),
		Actions:        []string{"a.b.c", "d.e.f"},
	})
	assert.Equal(t, "foo", OrganizationID(ctx))
}

func TestCredentials_apikey(t *testing.T) {
	ctx := newAPIKeyAuthContext(context.Background(), "foo", &tesseral.AuthenticateAPIKeyResponse{
		APIKeyID:       tesseral.String("foo"),
		OrganizationID: tesseral.String("foo"),
		Actions:        []string{"a.b.c", "d.e.f"},
	})
	assert.Equal(t, "foo", Credentials(ctx))
}

func TestHasPermission_apikey(t *testing.T) {
	ctx := newAPIKeyAuthContext(context.Background(), "foo", &tesseral.AuthenticateAPIKeyResponse{
		APIKeyID:       tesseral.String("foo"),
		OrganizationID: tesseral.String("foo"),
		Actions:        []string{"a.b.c", "d.e.f"},
	})
	assert.True(t, HasPermission(ctx, "a.b.c"))
	assert.True(t, HasPermission(ctx, "d.e.f"))
	assert.False(t, HasPermission(ctx, "x.y.z"))
}

func TestCredentialsType_apikey(t *testing.T) {
	ctx := newAPIKeyAuthContext(context.Background(), "foo", &tesseral.AuthenticateAPIKeyResponse{
		APIKeyID:       tesseral.String("foo"),
		OrganizationID: tesseral.String("foo"),
		Actions:        []string{"a.b.c", "d.e.f"},
	})
	assert.Equal(t, "api_key", CredentialsType(ctx))
}
