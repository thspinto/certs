package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func GenerateKeyPair() (*ecdsa.PrivateKey, jwk.Key, error) {
	raw, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating EC key: %w", err)
	}

	key, err := jwk.FromRaw(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("converting to JWK: %w", err)
	}

	if err := jwk.AssignKeyID(key); err != nil {
		return nil, nil, fmt.Errorf("assigning key ID: %w", err)
	}

	_ = key.Set(jwk.AlgorithmKey, jwa.ES384)
	_ = key.Set(jwk.KeyUsageKey, "sig")

	return raw, key, nil
}

func EncodePEM(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling EC private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}), nil
}
