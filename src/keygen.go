package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
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

	kid, err := keyIDFromPublicKey(&raw.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("deriving key ID: %w", err)
	}

	key, err := jwk.FromRaw(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("converting to JWK: %w", err)
	}

	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, nil, fmt.Errorf("setting key ID: %w", err)
	}

	_ = key.Set(jwk.AlgorithmKey, jwa.ES384)
	_ = key.Set(jwk.KeyUsageKey, "sig")

	return raw, key, nil
}

// keyIDFromPublicKey matches Kubernetes service-account key ID derivation.
func keyIDFromPublicKey(publicKey interface{}) (string, error) {
	publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("serializing public key to DER format: %w", err)
	}

	hasher := crypto.SHA256.New()
	hasher.Write(publicKeyDERBytes)
	publicKeyDERHash := hasher.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(publicKeyDERHash), nil
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
