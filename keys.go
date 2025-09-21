package main

import (
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/google/uuid"
)

type KeyRecord struct {
	KID       string
	Priv      *rsa.PrivateKey
	ExpiresAt time.Time
}

type KeyManager struct {
	active  KeyRecord
	expired KeyRecord
}

func NewKeyManager() (*KeyManager, error) {
	activeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	expiredKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &KeyManager{
		active: KeyRecord{
			KID:       "kid-" + uuid.NewString(),
			Priv:      activeKey,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		},
		expired: KeyRecord{
			KID:       "kid-" + uuid.NewString(),
			Priv:      expiredKey,
			ExpiresAt: time.Now().Add(-24 * time.Hour),
		},
	}, nil
}

func (k *KeyManager) Active() KeyRecord  { return k.active }
func (k *KeyManager) Expired() KeyRecord { return k.expired }
