package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func JWKSPath(baseDir, issuerName string) string {
	return filepath.Join(baseDir, "issuers", issuerName, ".well-known", "jwks.json")
}

func LoadJWKS(path string) (jwk.Set, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return jwk.NewSet(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	set, err := jwk.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return set, nil
}

func AppendPublicKey(set jwk.Set, privateJWK jwk.Key) error {
	pubKey, err := privateJWK.PublicKey()
	if err != nil {
		return fmt.Errorf("extracting public key: %w", err)
	}

	kid := privateJWK.KeyID()
	for i := 0; i < set.Len(); i++ {
		k, _ := set.Key(i)
		if k.KeyID() == kid {
			return fmt.Errorf("key %s already exists in JWKS", kid)
		}
	}

	if err := set.AddKey(pubKey); err != nil {
		return fmt.Errorf("adding key to set: %w", err)
	}
	return nil
}

func SaveJWKS(path string, set jwk.Set) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}
	data, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JWKS: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

func JWKSExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func OpenIDConfigPath(baseDir, issuerName string) string {
	return filepath.Join(baseDir, "issuers", issuerName, ".well-known", "openid-configuration")
}

type OpenIDConfiguration struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

func SaveOpenIDConfiguration(baseDir, issuerName, baseURL string) error {
	issuerURL := baseURL + "/" + issuerName
	cfg := OpenIDConfiguration{
		Issuer:                           issuerURL,
		JWKSURI:                          issuerURL + "/.well-known/jwks.json",
		ResponseTypesSupported:           []string{"id_token"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"ES384"},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling openid-configuration: %w", err)
	}
	data = append(data, '\n')
	path := OpenIDConfigPath(baseDir, issuerName)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}
