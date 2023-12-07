package tpm

import (
	"github.com/google/go-tpm-tools/proto/tpm"
	"go.uber.org/zap"
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

func (e *LocalCryptoEngine) Encrypt(dek []byte) (encDek []byte, err error) {
	zap.L().Debug("local-crypto-engine is processing a dek")

	b, found := e.cache.Get(string(dek))
	if found {
		return b.([]byte), nil
	}

	sb, err := e.tpmSealer.Seal(dek)
	if err != nil {
		return nil, err
	}

	encDek, err = proto.Marshal(sb)
	if err != nil {
		return nil, err
	}

	e.cache.Add(string(dek), encDek)
	zap.L().Debug("local-crypto-engine has sent encrypted dek")
	return
}

func (e *LocalCryptoEngine) Decrypt(encDek []byte) (plaintextDek []byte, err error) {
	zap.L().Debug("local-crypto-engine is decrypting an encrypted dek")

	b, found := e.cache.Get(string(encDek))
	if found {
		return b.([]byte), nil
	}

	sb := &tpm.SealedBytes{}
	err = proto.Unmarshal(encDek, sb)
	if err != nil {
		return nil, err
	}

	plaintextDek, err = e.tpmSealer.Unseal(sb)
	if err != nil {
		return nil, err
	}

	e.cache.Add(string(encDek), plaintextDek)
	zap.L().Debug("local-crypto-engine has sent plaintext dek back")
	return
}
