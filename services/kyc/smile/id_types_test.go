package smile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xeipuuv/gojsonschema"
)

var (
	configPath = "./id_types.json"
	schemaPath = "./id_types_schema.json"
)

func ValidateSmileIDConfig(filePath string) error {
	// Read the config file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Validate against JSON schema
	schemaPath := "./id_types_schema.json"
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

// TestValidateSmileIDConfig tests the validation of id_types.json
func TestValidateSmileIDConfig(t *testing.T) {

	// Ensure the real config and schema files exist
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatalf("Config file %s not found", configPath)
	}
	if _, err := os.Stat(schemaPath); os.IsNotExist(err) {
		t.Fatalf("Schema file %s not found", schemaPath)
	}

	// Create a temporary directory for modified configs
	tmpDir := t.TempDir()

	var err error

	t.Run("ValidConfig", func(t *testing.T) {
		err := ValidateSmileIDConfig(configPath)
		if err != nil {
			t.Errorf("Expected no error for valid config, got: %v", err)
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("Failed to read config: %v", err)
		}
		schemaLoader := gojsonschema.NewReferenceLoader("file://" + schemaPath)
		documentLoader := gojsonschema.NewBytesLoader(data)
		result, err := gojsonschema.Validate(schemaLoader, documentLoader)
		if err != nil {
			t.Fatalf("Schema validation error: %v", err)
		}
		if !result.Valid() {
			t.Errorf("Schema validation failed: %v", result.Errors())
		}
	})

	t.Run("EmptyContinents", func(t *testing.T) {
		invalidConfig := map[string]interface{}{"continents": []interface{}{}}
		tmpPath := filepath.Join(tmpDir, "empty_continents.json")
		data, _ := json.Marshal(invalidConfig)
		if err := os.WriteFile(tmpPath, data, 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		err := ValidateSmileIDConfig(tmpPath)
		if err == nil {
			t.Errorf("Expected schema validation error, got nil")
		} else if !strings.Contains(err.Error(), "continents: Array must have at least 1 items") {
			t.Errorf("Expected error containing 'continents: Array must have at least 1 items', got: %v", err)
		}
	})

	t.Run("EmptyContinentName", func(t *testing.T) {
		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("Failed to read config: %v", err)
		}
		var config map[string]interface{}
		if err := json.Unmarshal(data, &config); err != nil {
			t.Fatalf("Failed to parse config: %v", err)
		}

		continents := config["continents"].([]interface{})
		continent := continents[0].(map[string]interface{})
		continent["name"] = ""
		tmpPath := filepath.Join(tmpDir, "empty_continent_name.json")
		data, _ = json.Marshal(config)
		if err := os.WriteFile(tmpPath, data, 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		err = ValidateSmileIDConfig(tmpPath)
		if err == nil {
			t.Errorf("Expected schema validation error, got nil")
		} else if !strings.Contains(err.Error(), "name: String length must be greater than or equal to 1") {
			t.Errorf("Expected error containing 'name: String length must be greater than or equal to 1', got: %v", err)
		}
	})

	t.Run("EmptyCountries", func(t *testing.T) {
		invalidConfig := map[string]interface{}{
			"continents": []interface{}{
				map[string]interface{}{
					"name":      "Africa",
					"countries": []interface{}{},
				},
			},
		}
		tmpPath := filepath.Join(tmpDir, "empty_countries.json")
		data, _ := json.Marshal(invalidConfig)
		if err := os.WriteFile(tmpPath, data, 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		err = ValidateSmileIDConfig(tmpPath)
		if err == nil {
			t.Errorf("Expected schema validation error, got nil")
		} else if !strings.Contains(err.Error(), "continents.0.countries: Array must have at least 1 items") {
			t.Errorf("Expected error containing 'continents.0.countries: Array must have at least 1 items', got: %v", err)
		}
	})

	t.Run("InvalidCountryCode", func(t *testing.T) {
		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("Failed to read config: %v", err)
		}
		var config map[string]interface{}
		if err := json.Unmarshal(data, &config); err != nil {
			t.Fatalf("Failed to parse config: %v", err)
		}

		continents := config["continents"].([]interface{})
		countries := continents[0].(map[string]interface{})["countries"].([]interface{})
		country := countries[0].(map[string]interface{})
		country["code"] = "D1"
		tmpPath := filepath.Join(tmpDir, "invalid_country_code.json")
		data, _ = json.Marshal(config)
		if err := os.WriteFile(tmpPath, data, 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		err = ValidateSmileIDConfig(tmpPath)
		if err == nil {
			t.Errorf("Expected schema validation error, got nil")
		} else if !strings.Contains(err.Error(), "code: Does not match pattern '^[A-Z]{2}$'") {
			t.Errorf("Expected error containing 'code: Does not match pattern '^[A-Z]{2}$'', got: %v", err)
		}
	})

	t.Run("DuplicateCountryCode", func(t *testing.T) {
		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("Failed to read config: %v", err)
		}
		var config map[string]interface{}
		if err := json.Unmarshal(data, &config); err != nil {
			t.Fatalf("Failed to parse config: %v", err)
		}

		continents := config["continents"].([]interface{})
		countries := continents[0].(map[string]interface{})["countries"].([]interface{})
		duplicateCountry := countries[0]
		countries = append(countries, duplicateCountry)
		continents[0].(map[string]interface{})["countries"] = countries
		tmpPath := filepath.Join(tmpDir, "duplicate_country_code.json")
		data, _ = json.Marshal(config)
		if err := os.WriteFile(tmpPath, data, 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		err = ValidateSmileIDConfig(tmpPath)
		if err != nil {
			t.Errorf("Expected no error since schema allows duplicate country codes, got: %v", err)
		}
	})

	t.Run("EmptyIDTypes", func(t *testing.T) {
		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("Failed to read config: %v", err)
		}
		var config map[string]interface{}
		if err := json.Unmarshal(data, &config); err != nil {
			t.Fatalf("Failed to parse config: %v", err)
		}

		continents := config["continents"].([]interface{})
		countries := continents[0].(map[string]interface{})["countries"].([]interface{})
		country := countries[0].(map[string]interface{})
		country["id_types"] = []interface{}{}
		tmpPath := filepath.Join(tmpDir, "empty_id_types.json")
		data, _ = json.Marshal(config)
		if err := os.WriteFile(tmpPath, data, 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		err = ValidateSmileIDConfig(tmpPath)
		if err == nil {
			t.Errorf("Expected schema validation error, got nil")
		} else if !strings.Contains(err.Error(), "continents.0.countries.0.id_types: Array must have at least 1 items") {
			t.Errorf("Expected error containing 'continents.0.countries.0.id_types: Array must have at least 1 items', got: %v", err)
		}
	})

	t.Run("EmptyIDType", func(t *testing.T) {
		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("Failed to read config: %v", err)
		}
		var config map[string]interface{}
		if err := json.Unmarshal(data, &config); err != nil {
			t.Fatalf("Failed to parse config: %v", err)
		}

		continents := config["continents"].([]interface{})
		countries := continents[0].(map[string]interface{})["countries"].([]interface{})
		idTypes := countries[0].(map[string]interface{})["id_types"].([]interface{})
		idType := idTypes[0].(map[string]interface{})
		idType["type"] = ""
		tmpPath := filepath.Join(tmpDir, "empty_id_type.json")
		data, _ = json.Marshal(config)
		if err := os.WriteFile(tmpPath, data, 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		err = ValidateSmileIDConfig(tmpPath)
		if err == nil {
			t.Errorf("Expected schema validation error, got nil")
		} else if !strings.Contains(err.Error(), "type: String length must be greater than or equal to 1") {
			t.Errorf("Expected error containing 'type: String length must be greater than or equal to 1', got: %v", err)
		}
	})

	t.Run("InvalidVerificationMethod", func(t *testing.T) {
		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("Failed to read config: %v", err)
		}
		var config map[string]interface{}
		if err := json.Unmarshal(data, &config); err != nil {
			t.Fatalf("Failed to parse config: %v", err)
		}

		continents := config["continents"].([]interface{})
		countries := continents[0].(map[string]interface{})["countries"].([]interface{})
		idTypes := countries[0].(map[string]interface{})["id_types"].([]interface{})
		idType := idTypes[0].(map[string]interface{})
		idType["verification_method"] = "invalid"
		tmpPath := filepath.Join(tmpDir, "invalid_verification_method.json")
		data, _ = json.Marshal(config)
		if err := os.WriteFile(tmpPath, data, 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		err = ValidateSmileIDConfig(tmpPath)
		if err == nil {
			t.Errorf("Expected schema validation error, got nil")
		} else if !strings.Contains(err.Error(), "continents.0.countries.0.id_types.0.verification_method: continents.0.countries.0.id_types.0.verification_method must be one of the following: \"biometric_kyc\", \"doc_verification\"") {
			t.Errorf("Expected error containing 'continents.0.countries.0.id_types.0.verification_method must be one of the following: \"biometric_kyc\", \"doc_verification\"', got: %v", err)
		}
	})

	t.Run("AddNewCountry", func(t *testing.T) {
		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("Failed to read config: %v", err)
		}
		var config map[string]interface{}
		if err := json.Unmarshal(data, &config); err != nil {
			t.Fatalf("Failed to parse config: %v", err)
		}

		continents := config["continents"].([]interface{})
		for i, continent := range continents {
			if continent.(map[string]interface{})["name"] == "Africa" {
				countries := continent.(map[string]interface{})["countries"].([]interface{})
				newCountry := map[string]interface{}{
					"name": "Testlandia",
					"code": "XX",
					"id_types": []interface{}{
						map[string]interface{}{
							"type":                "PASSPORT",
							"verification_method": "doc_verification",
						},
					},
				}
				countries = append(countries, newCountry)
				continent.(map[string]interface{})["countries"] = countries
				continents[i] = continent
				break
			}
		}
		config["continents"] = continents
		tmpPath := filepath.Join(tmpDir, "add_new_country.json")
		data, _ = json.Marshal(config)
		if err := os.WriteFile(tmpPath, data, 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		err = ValidateSmileIDConfig(tmpPath)
		if err != nil {
			t.Errorf("Expected no error when adding new country, got: %v", err)
		}
	})

	t.Run("AdditionalProperties", func(t *testing.T) {
		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("Failed to read config: %v", err)
		}
		var config map[string]interface{}
		if err := json.Unmarshal(data, &config); err != nil {
			t.Fatalf("Failed to parse config: %v", err)
		}

		continents := config["continents"].([]interface{})
		countries := continents[0].(map[string]interface{})["countries"].([]interface{})
		country := countries[0].(map[string]interface{})
		country["extra_field"] = "invalid"
		tmpPath := filepath.Join(tmpDir, "additional_properties.json")
		data, _ = json.Marshal(config)
		if err := os.WriteFile(tmpPath, data, 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		err = ValidateSmileIDConfig(tmpPath)
		if err == nil {
			t.Errorf("Expected schema validation error, got nil")
		} else if !strings.Contains(err.Error(), "continents.0.countries.0: Additional property extra_field is not allowed") {
			t.Errorf("Expected error containing 'continents.0.countries.0: Additional property extra_field is not allowed', got: %v", err)
		}
	})
}

// TestFullConfig tests the full id_types.json
func TestFullConfig(t *testing.T) {
	// Validate the config
	err := ValidateSmileIDConfig(configPath)
	if err != nil {
		t.Fatalf("Validation failed for full config: %v", err)
	}

	// Load config for additional checks
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read full config: %v", err)
	}
	var config SmileIDConfig
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("Failed to parse full config: %v", err)
	}

	// Verify region coverage (6 regions)
	expectedRegions := map[string]bool{
		"Africa":                   false,
		"Asia and the Middle East": false,
		"Europe":                   false,
		"North America":            false,
		"Oceania":                  false,
		"South America":            false,
	}
	for _, continent := range config.Continents {
		if _, exists := expectedRegions[continent.Name]; exists {
			expectedRegions[continent.Name] = true
		}
	}
	for region, found := range expectedRegions {
		if !found {
			t.Errorf("Region %s not found in config", region)
		}
	}

	// Verify country count (>= 50)
	totalCountries := 0
	for _, continent := range config.Continents {
		totalCountries += len(continent.Countries)
	}
	if totalCountries < 50 {
		t.Errorf("Expected at least 50 countries, got %d", totalCountries)
	}

	// Verify ID type count (>= 200)
	totalIDTypes := 0
	for _, continent := range config.Continents {
		for _, country := range continent.Countries {
			totalIDTypes += len(country.IDTypes)
		}
	}
	if totalIDTypes < 200 {
		t.Errorf("Expected at least 200 ID types, got %d", totalIDTypes)
	}

	// Spot-check specific countries
	for _, continent := range config.Continents {
		for _, country := range continent.Countries {
			if continent.Name == "Africa" && country.Code == "DZ" {
				if len(country.IDTypes) != 6 {
					t.Errorf("Expected 6 ID types for Algeria, got %d", len(country.IDTypes))
				}
				foundDriversLicense := false
				for _, idType := range country.IDTypes {
					if idType.Type == "DRIVERS_LICENSE" {
						foundDriversLicense = true
						break
					}
				}
				if !foundDriversLicense {
					t.Errorf("Expected DRIVERS_LICENSE for Algeria")
				}
			}
			if continent.Name == "Africa" && country.Code == "AO" {
				if len(country.IDTypes) != 9 {
					t.Errorf("Expected 9 ID types for Angola, got %d", len(country.IDTypes))
				}
				foundVoterID := false
				for _, idType := range country.IDTypes {
					if idType.Type == "VOTER_ID" {
						foundVoterID = true
						break
					}
				}
				if !foundVoterID {
					t.Errorf("Expected VOTER_ID for Angola")
				}
			}
		}
	}
}
