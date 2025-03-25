package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		wantKey     string
		wantErr     error
	}{
		{
			name:        "No Authorization Header",
			headerValue: "",
			wantKey:     "",
			wantErr:     ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Malformed Authorization Header - Missing ApiKey prefix",
			headerValue: "Bearer some-api-key",
			wantKey:     "",
			wantErr:     errors.New("malformed authorization header"),
		},
		{
			name:        "Malformed Authorization Header - No key after prefix",
			headerValue: "ApiKey",
			wantKey:     "",
			wantErr:     errors.New("malformed authorization header"),
		},
		{
			name:        "Valid Authorization Header",
			headerValue: "ApiKey my-secret-key",
			wantKey:     "my-secret-key",
			wantErr:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			if tt.headerValue != "" {
				headers.Set("Authorization", tt.headerValue)
			}

			gotKey, err := GetAPIKey(headers)

			if gotKey != tt.wantKey {
				t.Errorf("expected key: %v, got: %v", tt.wantKey, gotKey)
			}

			if (err != nil && tt.wantErr == nil) ||
				(err == nil && tt.wantErr != nil) ||
				(err != nil && tt.wantErr != nil && err.Error() != tt.wantErr.Error()) {
				t.Errorf("expected error: %v, got: %v", tt.wantErr, err)
			}
		})
	}
}
