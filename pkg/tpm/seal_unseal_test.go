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

	secret := "DO-NOT-LOSE-$1000000-this-should-not-be-leaked-BTC-token++DO-NOT-LOSE-$1000000-this-should-not-be-leaked-BTC-token"
	// secret := "\ufffd.H\u0013\ufffd\ufffd\ufffd\ufffd\ufffd\u000c\ufffd\u001bn\ufffd\u0007\\\ufffd\ufffd\ufffd\t^+\ufffd\ufffd\u0011v \ufffdpO[\ufffd"
	t.Logf("len(secret): %d", len(secret))

	s, err := tpmSealer.Seal([]byte(secret))
	require.NoError(t, err)

	sealedBlob, err := proto.Marshal(s)
	t.Logf("len(sealedSecret): %d", len(sealedBlob))
	require.NoError(t, err)

	require.NoError(t, os.WriteFile("btc.secret", sealedBlob, 0644))

	b, err := os.ReadFile("btc.secret")
	require.NoError(t, err)

	s = &tpm.SealedBytes{}
	err = proto.Unmarshal(b, s)
	require.NoError(t, err)

	txt, err := tpmSealer.Unseal(s)
	require.NoError(t, err)

	t.Logf("plaintext dek back to you is %s", txt)
}

func TestAnother(t *testing.T) {
	tpmDevice, err := tpm2.OpenTPM()
	require.NoError(t, err)

	tpmSealer, err := NewTPMSealer(&tpmDevice, 14)
	require.NoError(t, err)

	// secret := "DO-NOT-LOSE-$1000000-this-should-not-be-leaked-BTC-token++DO-NOT-LOSE-$1000000-this-should-not-be-leaked-BTC-token"
	secret := "\ufffd.H\u0013\ufffd\ufffd\ufffd\ufffd\ufffd\u000c\ufffd\u001bn\ufffd\u0007\\\ufffd\ufffd\ufffd\t^+\ufffd\ufffd\u0011v \ufffdpO[\ufffd"
	t.Logf("len(secret): %d", len(secret))

	s, err := tpmSealer.Seal([]byte(secret))
	require.NoError(t, err)

	sealedBlob, err := proto.Marshal(s)
	t.Logf("len(sealedSecret): %d", len(sealedBlob))
	require.NoError(t, err)

	merged, err := WrapCipherV2(sealedBlob, make([]byte, 190))
	require.NoError(t, err)
	t.Logf("len(mergedCipher): %d", len(merged))

	require.NoError(t, os.WriteFile("merged.secret", merged, 0644))
}
