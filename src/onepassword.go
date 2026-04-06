package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

func OPItemName(issuerName, kid string) string {
	return fmt.Sprintf("jwt-key/%s/%s", issuerName, kid)
}

func OPStorePrivateKey(vault, issuerName, kid string, pemData []byte) error {
	itemName := OPItemName(issuerName, kid)

	template := map[string]any{
		"title":    itemName,
		"category": "SECURE_NOTE",
		"fields": []map[string]any{
			{
				"id":      "notesPlain",
				"type":    "STRING",
				"value":   string(pemData),
				"purpose": "NOTES",
			},
		},
		"tags": []string{"jwt-key", issuerName},
	}

	payload, err := json.Marshal(template)
	if err != nil {
		return fmt.Errorf("marshaling template: %w", err)
	}

	cmd := exec.Command("op", "item", "create", "--vault", vault, "--format", "json")
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Stderr = os.Stderr

	if out, err := cmd.Output(); err != nil {
		return fmt.Errorf("op item create failed: %w (output: %s)", err, out)
	}
	return nil
}

type OPItem struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

func OPListKeys(vault, issuerName string) ([]OPItem, error) {
	cmd := exec.Command("op", "item", "list", "--vault", vault, "--tags", "jwt-key,"+issuerName, "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("op item list failed: %w", err)
	}
	var items []OPItem
	if err := json.Unmarshal(out, &items); err != nil {
		return nil, fmt.Errorf("parsing op output: %w", err)
	}
	return items, nil
}
