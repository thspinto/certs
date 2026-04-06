package main

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

var validName = regexp.MustCompile(`^[a-z0-9-]+$`)

type Config struct {
	Vault   string   `yaml:"vault"`
	Issuers []Issuer `yaml:"issuers"`
}

type Issuer struct {
	Name      string `yaml:"name"`
	Algorithm string `yaml:"algorithm"`
	OPVault   string `yaml:"op_vault"`
}

func (i Issuer) EffectiveVault(globalVault string) string {
	if i.OPVault != "" {
		return i.OPVault
	}
	return globalVault
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	if c.Vault == "" {
		return fmt.Errorf("vault is required")
	}
	if len(c.Issuers) == 0 {
		return fmt.Errorf("at least one issuer is required")
	}
	seen := make(map[string]bool)
	for _, iss := range c.Issuers {
		if !validName.MatchString(iss.Name) {
			return fmt.Errorf("issuer name %q must be lowercase alphanumeric with hyphens", iss.Name)
		}
		if seen[iss.Name] {
			return fmt.Errorf("duplicate issuer name %q", iss.Name)
		}
		seen[iss.Name] = true
		if iss.Algorithm != "ES384" {
			return fmt.Errorf("issuer %q: only ES384 is supported, got %q", iss.Name, iss.Algorithm)
		}
	}
	return nil
}

func (c *Config) FilterByName(name string) []Issuer {
	for _, iss := range c.Issuers {
		if iss.Name == name {
			return []Issuer{iss}
		}
	}
	return nil
}
