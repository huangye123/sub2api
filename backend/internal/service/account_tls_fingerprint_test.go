package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAccount_TLSFingerprintSupportedForOpenAI(t *testing.T) {
	tests := []struct {
		name     string
		account  Account
		supports bool
		enabled  bool
	}{
		{
			name: "openai oauth",
			account: Account{
				Platform: PlatformOpenAI,
				Type:     AccountTypeOAuth,
				Extra:    map[string]any{"enable_tls_fingerprint": true},
			},
			supports: true,
			enabled:  true,
		},
		{
			name: "openai api key",
			account: Account{
				Platform: PlatformOpenAI,
				Type:     AccountTypeAPIKey,
				Extra:    map[string]any{"enable_tls_fingerprint": true},
			},
			supports: true,
			enabled:  true,
		},
		{
			name: "anthropic oauth remains supported",
			account: Account{
				Platform: PlatformAnthropic,
				Type:     AccountTypeOAuth,
				Extra:    map[string]any{"enable_tls_fingerprint": true},
			},
			supports: true,
			enabled:  true,
		},
		{
			name: "unsupported platform ignores flag",
			account: Account{
				Platform: PlatformGemini,
				Type:     AccountTypeOAuth,
				Extra:    map[string]any{"enable_tls_fingerprint": true},
			},
			supports: false,
			enabled:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.supports, tt.account.SupportsTLSFingerprint())
			require.Equal(t, tt.enabled, tt.account.IsTLSFingerprintEnabled())
		})
	}
}

func TestAccount_GetTLSFingerprintProfileID(t *testing.T) {
	t.Run("numeric profile id", func(t *testing.T) {
		account := &Account{
			Platform: PlatformOpenAI,
			Type:     AccountTypeOAuth,
			Extra: map[string]any{
				"tls_fingerprint_profile_id": float64(42),
			},
		}
		require.Equal(t, int64(42), account.GetTLSFingerprintProfileID())
	})

	t.Run("random profile id is preserved", func(t *testing.T) {
		account := &Account{
			Platform: PlatformOpenAI,
			Type:     AccountTypeAPIKey,
			Extra: map[string]any{
				"tls_fingerprint_profile_id": int64(-1),
			},
		}
		require.Equal(t, int64(-1), account.GetTLSFingerprintProfileID())
	})
}
