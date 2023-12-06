package tpm

import (
	"os"
	"testing"

	"github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestSealUnsealData(t *testing.T) {
	tpmDevice, err := tpm2.OpenTPM()
	require.NoError(t, err)

	tpmSealer, err := NewTPMSealer(&tpmDevice, 14)
	require.NoError(t, err)

	s, err := tpmSealer.Seal("DO-NOT-LOSE-$1000000-this-should-not-be-leaked-BTC-token")
	require.NoError(t, err)

	sealedBlob, err := proto.Marshal(s)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile("btc.secret", sealedBlob, os.ModeDevice))

	b, err := os.ReadFile("btc.secret")
	require.NoError(t, err)

	s = &tpm.SealedBytes{}
	err = proto.Unmarshal(b, s)
	require.NoError(t, err)

	txt, err := tpmSealer.Unseal(s)
	require.NoError(t, err)

	t.Logf("plaintext dek back to you is %q", txt)
}
