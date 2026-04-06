package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate":
		if err := runGenerate(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "rotate":
		if err := runRotate(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		if err := runList(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: certs <command> [flags]

Commands:
  generate   Generate new key pairs for issuers
  rotate     Rotate keys for existing issuers (keeps previous keys)
  list       List keys in local JWKS files

Flags:
  --config   Path to config file (default: issuers.yaml)
  --issuer   Target a single issuer (default: all)
`)
}

func parseFlags(name string, args []string) (configPath, issuerName string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	cp := fs.String("config", "issuers.yaml", "path to config file")
	in := fs.String("issuer", "", "target a single issuer (default: all)")
	fs.Parse(args)
	return *cp, *in
}

func resolveIssuers(cfg *Config, issuerName string) ([]Issuer, error) {
	if issuerName == "" {
		return cfg.Issuers, nil
	}
	issuers := cfg.FilterByName(issuerName)
	if len(issuers) == 0 {
		return nil, fmt.Errorf("issuer %q not found in config", issuerName)
	}
	return issuers, nil
}

func runGenerate(args []string) error {
	configPath, issuerName := parseFlags("generate", args)
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	issuers, err := resolveIssuers(cfg, issuerName)
	if err != nil {
		return err
	}

	for _, iss := range issuers {
		if err := generateForIssuer(cfg.Vault, iss); err != nil {
			return fmt.Errorf("issuer %s: %w", iss.Name, err)
		}
	}
	return nil
}

func runRotate(args []string) error {
	configPath, issuerName := parseFlags("rotate", args)
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	issuers, err := resolveIssuers(cfg, issuerName)
	if err != nil {
		return err
	}

	for _, iss := range issuers {
		jwksPath := JWKSPath(".", iss.Name)
		if !JWKSExists(jwksPath) {
			return fmt.Errorf("issuer %s: no existing JWKS found at %s (use 'generate' first)", iss.Name, jwksPath)
		}
		if err := generateForIssuer(cfg.Vault, iss); err != nil {
			return fmt.Errorf("issuer %s: %w", iss.Name, err)
		}
	}
	return nil
}

func generateForIssuer(globalVault string, iss Issuer) error {
	vault := iss.EffectiveVault(globalVault)

	raw, jwkKey, err := GenerateKeyPair()
	if err != nil {
		return err
	}

	kid := jwkKey.KeyID()

	pemData, err := EncodePEM(raw)
	if err != nil {
		return err
	}

	// Store private key in 1Password FIRST
	if err := OPStorePrivateKey(vault, iss.Name, kid, pemData); err != nil {
		return fmt.Errorf("storing private key: %w", err)
	}

	// Then publish public key to JWKS
	jwksPath := JWKSPath(".", iss.Name)
	set, err := LoadJWKS(jwksPath)
	if err != nil {
		return err
	}
	if err := AppendPublicKey(set, jwkKey); err != nil {
		return err
	}
	if err := SaveJWKS(jwksPath, set); err != nil {
		return err
	}

	fmt.Printf("%s: generated key %s\n", iss.Name, kid)
	fmt.Printf("  JWKS:       %s (%d keys)\n", jwksPath, set.Len())
	fmt.Printf("  1Password:  %s in vault %q\n", OPItemName(iss.Name, kid), vault)
	return nil
}

func runList(args []string) error {
	configPath, issuerName := parseFlags("list", args)
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	issuers, err := resolveIssuers(cfg, issuerName)
	if err != nil {
		return err
	}

	for _, iss := range issuers {
		jwksPath := JWKSPath(".", iss.Name)
		set, err := LoadJWKS(jwksPath)
		if err != nil {
			return fmt.Errorf("issuer %s: %w", iss.Name, err)
		}

		fmt.Printf("%s (%s):\n", iss.Name, jwksPath)
		if set.Len() == 0 {
			fmt.Println("  (no keys)")
			continue
		}
		for i := 0; i < set.Len(); i++ {
			k, _ := set.Key(i)
			fmt.Printf("  [%d] kid=%s alg=%s crv=%s use=%s\n",
				i, k.KeyID(), k.Algorithm().String(),
				getField(k, "crv"), getField(k, "use"))
		}
	}
	return nil
}

func getField(k jwk.Key, name string) string {
	v, ok := k.Get(name)
	if ok {
		return fmt.Sprint(v)
	}
	return ""
}
