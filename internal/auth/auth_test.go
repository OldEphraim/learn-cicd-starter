package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	// Test case where no Authorization header is provided
	headers := http.Header{}
	_, err := GetAPIKey(headers)

	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKey_MalformedAuthHeader(t *testing.T) {
	// Test case where the Authorization header is malformed
	headers := http.Header{}
	headers.Set("Authorization", "Bearer abc123")

	_, err := GetAPIKey(headers)

	expectedErr := "malformed authorization header"
	if err == nil || err.Error() != expectedErr {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

func TestGetAPIKey_ValidAPIKey(t *testing.T) {
	// Test case where a valid API key is provided
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey abc123")

	apiKey, err := GetAPIKey(headers)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	expectedAPIKey := "abc123"
	if apiKey != expectedAPIKey {
		t.Errorf("expected API key %v, got %v", expectedAPIKey, apiKey)
	}
}
