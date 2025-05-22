package auth

import (
	"regexp"
)

var (
	jwtRegex    = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
	apiKeyRegex = regexp.MustCompile(`^[a-z0-9_]+$`)
)

// IsJWTFormat checks whether the string matches the structure of a JWT.
func IsJWTFormat(value string) bool {
	return jwtRegex.MatchString(value)
}

// IsAPIKeyFormat checks whether the string is a valid API key format.
func IsAPIKeyFormat(value string) bool {
	return apiKeyRegex.MatchString(value)
}
