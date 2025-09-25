package services

import (
	"encoding/json"
	"testing"
)

func TestParseUserOpErrorJSON(t *testing.T) {
	engineService := NewEngineService()

	// Test 1: TokenNotSupported error
	tokenErrorJSON := `{
		"error": {
			"stage": "BUILDING",
			"message": "Paymaster error on chain 8453 at https://8453.bundler.thirdweb.com/v2: HTTP error 500 with body: {\"error\":\"Internal server error\",\"cause\":\"Invalid estimation result: UserOperation reverted during simulation with reason: 0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000011546f6b656e4e6f74537570706f72746564000000000000000000000000000000000000\",\"code\":500}",
			"errorCode": "USER_OP_BUILD_FAILED",
			"nonce_used": "0xe7f2cf180121bfa116b64646864e17c00000000000000000000000000000000",
			"inner_error": {
				"kind": {
					"body": "{\"error\":\"Internal server error\",\"cause\":\"Invalid estimation result: UserOperation reverted during simulation with reason: 0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000011546f6b656e4e6f74537570706f72746564000000000000000000000000000000000000\",\"code\":500}",
					"type": "TRANSPORT_HTTP_ERROR",
					"status": 500
				},
				"type": "PAYMASTER_ERROR",
				"message": "HTTP error 500 with body: {\"error\":\"Internal server error\",\"cause\":\"Invalid estimation result: UserOperation reverted during simulation with reason: 0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000011546f6b656e4e6f74537570706f72746564000000000000000000000000000000000000\",\"code\":500}",
				"rpc_url": "https://8453.bundler.thirdweb.com/v2",
				"chain_id": 8453
			},
			"account_address": "0xd9fa0881e605bf0c26628e1c540dab2fb39d46de",
			"had_deployment_lock": true
		},
		"finalAttemptNumber": 1
	}`

	var errorData map[string]interface{}
	json.Unmarshal([]byte(tokenErrorJSON), &errorData)

	result := engineService.ParseUserOpErrorJSON(errorData)
	expected := "TokenNotSupported"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}

	// Test 2: OnlyAggregator error
	aggregatorErrorJSON := `{
		"error": {
			"stage": "BUILDING",
			"message": "Paymaster error on chain 84532 at https://84532.bundler.thirdweb.com/v2: HTTP error 500 with body: {\"error\":\"Internal server error\",\"cause\":\"Invalid estimation result: UserOperation reverted during simulation with reason: 0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000e4f6e6c7941676772656761746f72000000000000000000000000000000000000\",\"code\":500}",
			"errorCode": "USER_OP_BUILD_FAILED",
			"nonce_used": "0x5905c8391e190ce5ce44f9b0311b085c00000000000000000000000000000000",
			"inner_error": {
				"kind": {
					"body": "{\"error\":\"Internal server error\",\"cause\":\"Invalid estimation result: UserOperation reverted during simulation with reason: 0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000e4f6e6c7941676772656761746f72000000000000000000000000000000000000\",\"code\":500}",
					"type": "TRANSPORT_HTTP_ERROR",
					"status": 500
				},
				"type": "PAYMASTER_ERROR",
				"message": "HTTP error 500 with body: {\"error\":\"Internal server error\",\"cause\":\"Invalid estimation result: UserOperation reverted during simulation with reason: 0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000e4f6e6c7941676772656761746f72000000000000000000000000000000000000\",\"code\":500}",
				"rpc_url": "https://84532.bundler.thirdweb.com/v2",
				"chain_id": 84532
			},
			"account_address": "0x484a8345d0d889eb974c6d5525b6ba5744045f3b",
			"had_deployment_lock": true
		},
		"finalAttemptNumber": 1
	}`

	json.Unmarshal([]byte(aggregatorErrorJSON), &errorData)

	result2 := engineService.ParseUserOpErrorJSON(errorData)
	expected2 := "OnlyAggregator"

	if result2 != expected2 {
		t.Errorf("Expected %s, got %s", expected2, result2)
	}
}
