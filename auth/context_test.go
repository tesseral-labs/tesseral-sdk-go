package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tesseral-labs/tesseral-sdk-go"
)

func TestOrganizationID(t *testing.T) {
	ctx := newAuthContext(context.Background(), "", &tesseral.AccessTokenClaims{Organization: &tesseral.AccessTokenOrganization{ID: "foo"}})
	assert.Equal(t, "foo", OrganizationID(ctx))
}

func TestCredentials(t *testing.T) {
	ctx := newAuthContext(context.Background(), "foo", nil)
	assert.Equal(t, "foo", Credentials(ctx))
}

func TestAccessTokenClaims(t *testing.T) {
	want := &tesseral.AccessTokenClaims{Sub: "foo"}
	ctx := newAuthContext(context.Background(), "", want)
	got, err := AccessTokenClaims(ctx)
	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestHasPermission(t *testing.T) {
	ctx := newAuthContext(context.Background(), "", &tesseral.AccessTokenClaims{Actions: []string{"a.b.c", "d.e.f"}})
	assert.True(t, HasPermission(ctx, "a.b.c"))
	assert.True(t, HasPermission(ctx, "d.e.f"))
	assert.False(t, HasPermission(ctx, "x.y.z"))
}
