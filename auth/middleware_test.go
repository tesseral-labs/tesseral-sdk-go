package auth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractAccessToken(t *testing.T) {
	testCases := []struct {
		name      string
		projectID string
		req       *http.Request
		want      string
	}{
		{
			name:      "in Authorization header",
			projectID: "project_foo",
			req: &http.Request{
				Header: http.Header{
					"Authorization": []string{"Bearer aaa"},
				},
			},
			want: "aaa",
		},
		{
			name:      "in cookie",
			projectID: "project_foo",
			req: &http.Request{
				Header: http.Header{
					"Cookie": []string{"tesseral_project_foo_access_token=aaa"},
				},
			},
			want: "aaa",
		},
		{
			name:      "not found",
			projectID: "project_foo",
			req: &http.Request{
				Header: http.Header{
					"Authorization": []string{"aaa"},
					"Cookie":        []string{"tesseral_project_bar_access_token=aaa"},
				},
			},
			want: "",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCredential(tt.projectID, tt.req)
			assert.Equal(t, tt.want, got)
		})
	}
}
