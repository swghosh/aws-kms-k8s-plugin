package tpm

import (
	"io"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
)

type TPMSealer struct {
	TPMDevice *io.ReadWriteCloser

	srk    *client.Key
	pcrSel tpm2.PCRSelection
}

func NewTPMSealer(tpmDevice *io.ReadWriteCloser, pcrToUse int) (*TPMSealer, error) {
	srk, err := client.StorageRootKeyECC(*tpmDevice)
	if err != nil {
		return nil, err
	}
	sel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{pcrToUse}}

	t := TPMSealer{
		TPMDevice: tpmDevice,
		srk:       srk,
		pcrSel:    sel,
	}
	return &t, nil
}

func (t *TPMSealer) Seal(secret string) (*tpm.SealedBytes, error) {
	sealedBlob, err := t.srk.Seal([]byte(secret), client.SealOpts{Current: t.pcrSel})
	return sealedBlob, err
}

func (t *TPMSealer) Unseal(sealedBlob *tpm.SealedBytes) (plaintextSecret string, err error) {
	secretBytes, err := t.srk.Unseal(sealedBlob, client.UnsealOpts{CertifyCurrent: t.pcrSel})
	if err != nil {
		return "", err
	}
	return string(secretBytes[:]), nil
}
