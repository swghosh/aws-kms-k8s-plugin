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
	key := client.SRKTemplateECC()

	srk, err := client.NewCachedKey(*tpmDevice, tpm2.HandleOwner, key, client.SRKReservedHandle)
	if err != nil {
		return nil, err
	}
	_ = pcrToUse
	sel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{}}

	t := TPMSealer{
		TPMDevice: tpmDevice,
		srk:       srk,
		pcrSel:    sel,
	}
	return &t, nil
}

func (t *TPMSealer) Seal(secret []byte) (*tpm.SealedBytes, error) {
	sealedBlob, err := t.srk.Seal(secret, client.SealOpts{Current: t.pcrSel})
	sealedBlob.CertifiedPcrs = nil
	sealedBlob.Pcrs = []uint32{}
	return sealedBlob, err
}

func (t *TPMSealer) Unseal(sealedBlob *tpm.SealedBytes) (plaintextSecret []byte, err error) {
	secretBytes, err := t.srk.Unseal(sealedBlob, client.UnsealOpts{CertifyCurrent: t.pcrSel})
	if err != nil {
		return nil, err
	}
	return secretBytes, nil
}
