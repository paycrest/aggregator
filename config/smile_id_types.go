package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/xeipuuv/gojsonschema"
)

type IDType struct {
	Type               string `json:"type"`
	VerificationMethod string `json:"verification_method"`
}

type Country struct {
	Name    string   `json:"name"`
	Code    string   `json:"code"`
	IDTypes []IDType `json:"id_types"`
}

type Continent struct {
	Name      string    `json:"name"`
	Countries []Country `json:"countries"`
}

type SmileIDConfig struct {
	Continents []Continent `json:"continents"`
}

func ValidateSmileIDConfig(filePath string) error {
	// Read the config file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Validate against JSON schema
	schemaPath := "./smile_id_types_schema.json"
	schemaLoader := gojsonschema.NewReferenceLoader("file://" + schemaPath)
	documentLoader := gojsonschema.NewBytesLoader(data)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return fmt.Errorf("failed to validate schema: %w", err)
	}
	if !result.Valid() {
		var errors []string
		for _, e := range result.Errors() {
			errors = append(errors, e.String())
		}
		return fmt.Errorf("schema validation failed: %v", errors)
	}

	// Ensure JSON is parseable into SmileIDConfig
	var config SmileIDConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	return nil
}
