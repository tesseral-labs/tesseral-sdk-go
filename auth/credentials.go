package auth

import (
	"regexp"
)

var (
	jwtRegex    = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
	apiKeyRegex = regexp.MustCompile(`^[a-z0-9_]+$`)
)

func isJWTFormat(value string) bool {
	return jwtRegex.MatchString(value)
}

func isAPIKeyFormat(value string) bool {
	return apiKeyRegex.MatchString(value)
}
