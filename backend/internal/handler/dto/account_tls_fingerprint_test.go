package dto

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

func TestAccountFromServiceShallow_MapsOpenAITLSFingerprint(t *testing.T) {
	account := &service.Account{
		ID:       1,
		Name:     "openai",
		Platform: service.PlatformOpenAI,
		Type:     service.AccountTypeOAuth,
		Extra: map[string]any{
			"enable_tls_fingerprint":     true,
			"tls_fingerprint_profile_id": float64(42),
		},
	}

	got := AccountFromServiceShallow(account)

	require.NotNil(t, got.EnableTLSFingerprint)
	require.True(t, *got.EnableTLSFingerprint)
	require.NotNil(t, got.TLSFingerprintProfileID)
	require.Equal(t, int64(42), *got.TLSFingerprintProfileID)
}

func TestAccountFromServiceShallow_OmitsTLSFingerprintForUnsupportedPlatform(t *testing.T) {
	account := &service.Account{
		ID:       1,
		Name:     "gemini",
		Platform: service.PlatformGemini,
		Type:     service.AccountTypeOAuth,
		Extra: map[string]any{
			"enable_tls_fingerprint":     true,
			"tls_fingerprint_profile_id": float64(42),
		},
	}

	got := AccountFromServiceShallow(account)

	require.Nil(t, got.EnableTLSFingerprint)
	require.Nil(t, got.TLSFingerprintProfileID)
}
