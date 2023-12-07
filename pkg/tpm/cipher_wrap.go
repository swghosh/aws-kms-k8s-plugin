package tpm

import (
	"bytes"
	"encoding/gob"

	"github.com/gogo/protobuf/proto"
)

func WrapCipher(kmsCipher []byte, tpmCipher []byte) []byte {
	secret := &Secret{
		Kmsenc: kmsCipher,
		Tpmenc: tpmCipher,
	}
	return []byte(secret.String())
}

func UnwrapCipher(secretBlob []byte) (*Secret, error) {
	secret := &Secret{}
	err := proto.Unmarshal(secretBlob, secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

type MergedSecret struct {
	Cipher1 []byte
	Cipher2 []byte
}

func WrapCipherV2(cipher1 []byte, cipher2 []byte) ([]byte, error) {
	secret := &MergedSecret{
		Cipher1: cipher1,
		Cipher2: cipher2,
	}

	var b bytes.Buffer
	e := gob.NewEncoder(&b)
	if err := e.Encode(secret); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func UnwrapCipherV2(mergedCipher []byte) (*MergedSecret, error) {
	secret := &MergedSecret{}

	copiedB := make([]byte, len(mergedCipher))
	copy(copiedB, mergedCipher)

	b := bytes.NewBuffer(copiedB)
	d := gob.NewDecoder(b)
	if err := d.Decode(secret); err != nil {
		return nil, err
	}

	return secret, nil
}
