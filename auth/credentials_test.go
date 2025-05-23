package auth

import (
	"testing"
)

func TestIsJWTFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name: "valid JWT format",
			input: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
				".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6" +
				"IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" +
				".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expected: true,
		},
		{
			name:     "missing a part",
			input:    "header.payload",
			expected: false,
		},
		{
			name:     "invalid characters",
			input:    "header.payload.with=illegal&chars",
			expected: false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "extra segments",
			input:    "a.b.c.d",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isJWTFormat(tt.input)
			if result != tt.expected {
				t.Errorf("IsJWTFormat(%q) = %v; want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsAPIKeyFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid API key format",
			input:    "abc123_underscore",
			expected: true,
		},
		{
			name:     "uppercase letters",
			input:    "ABC123",
			expected: false,
		},
		{
			name:     "invalid characters",
			input:    "key-with-dash",
			expected: false,
		},
		{
			name:     "spaces",
			input:    "key with space",
			expected: false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAPIKeyFormat(tt.input)
			if result != tt.expected {
				t.Errorf("IsAPIKeyFormat(%q) = %v; want %v", tt.input, result, tt.expected)
			}
		})
	}
}
