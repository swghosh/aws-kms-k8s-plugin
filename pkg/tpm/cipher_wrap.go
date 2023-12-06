package tpm

import "github.com/gogo/protobuf/proto"

func WrapCipher(kmsCipher []byte, tpmCipher string) []byte {
	secret := &Secret{
		Kmsenc: kmsCipher,
		Tpmenc: []byte(tpmCipher),
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
