package tpm

import (
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"
)

func TestSealUnsealData(t *testing.T) {
	tpmDevice, err := tpm2.OpenTPM()
	require.NoError(t, err)

	tpmSealer, err := NewTPMSealer(&tpmDevice, 14)
	require.NoError(t, err)

	s, err := tpmSealer.Seal("x-private-dek-important-key")
	require.NoError(t, err)

	txt, err := tpmSealer.Unseal(s)
	require.NoError(t, err)

	t.Fatalf("plaintext dek back to you is %q", txt)
}
