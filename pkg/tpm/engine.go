package tpm

import (
	"github.com/google/go-tpm-tools/proto/tpm"
	"google.golang.org/protobuf/proto"
	"k8s.io/utils/lru"
)

type LocalCryptoEngine struct {
	tpmSealer *TPMSealer
	cache     *lru.Cache
}

func NewLocalCryptoEngine(sealer *TPMSealer, cacheSize int) *LocalCryptoEngine {
	var cache *lru.Cache

	if cacheSize > 0 {
		cache = lru.New(cacheSize)
	}

	return &LocalCryptoEngine{
		tpmSealer: sealer,
		cache:     cache,
	}
}

func (e *LocalCryptoEngine) Encrypt(dek string) (encDek string, err error) {
	b, found := e.cache.Get(dek)
	if found {
		return b.(string), nil
	}

	sb, err := e.tpmSealer.Seal(dek)
	if err != nil {
		return "", err
	}

	encDek = sb.String()

	e.cache.Add(dek, encDek)
	return
}

func (e *LocalCryptoEngine) Decrypt(encDek string) (plaintextDek string, err error) {
	b, found := e.cache.Get(encDek)
	if found {
		return b.(string), nil
	}

	sb := &tpm.SealedBytes{}

	bString := b.(string)
	err = proto.Unmarshal([]byte(bString), sb)
	if err != nil {
		return "", err
	}

	plaintextDek, err = e.tpmSealer.Unseal(sb)
	if err != nil {
		return "", err
	}

	e.cache.Add(encDek, plaintextDek)
	return
}
