package main

import (
	"encoding/json"
	"fmt"

	"github.com/paycrest/aggregator/services"
)

func main() {
	engineService := services.NewEngineService()

	// Example 1: TokenNotSupported error
	tokenErrorJSON := `{
		"error": {
			"stage": "BUILDING",
			"message": "Paymaster error on chain 8453 at https://8453.bundler.thirdweb.com/v2: HTTP error 500 with body: {\"error\":\"Internal server error\",\"cause\":\"Invalid estimation result: UserOperation reverted during simulation with reason: 0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000011546f6b656e4e6f74537570706f72746564000000000000000000000000000000000000\",\"code\":500}",
			"errorCode": "USER_OP_BUILD_FAILED",
			"inner_error": {
				"kind": {
					"body": "{\"error\":\"Internal server error\",\"cause\":\"Invalid estimation result: UserOperation reverted during simulation with reason: 0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000011546f6b656e4e6f74537570706f72746564000000000000000000000000000000000000\",\"code\":500}"
				}
			}
		}
	}`

	var errorData map[string]interface{}
	json.Unmarshal([]byte(tokenErrorJSON), &errorData)

	decodedReason := engineService.ParseUserOpErrorJSON(errorData)
	fmt.Printf("Decoded error: %s\n", decodedReason)

	// Example 2: OnlyAggregator error
	aggregatorErrorJSON := `{
		"error": {
			"stage": "BUILDING",
			"message": "Paymaster error on chain 84532 at https://84532.bundler.thirdweb.com/v2: HTTP error 500 with body: {\"error\":\"Internal server error\",\"cause\":\"Invalid estimation result: UserOperation reverted during simulation with reason: 0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000e4f6e6c7941676772656761746f72000000000000000000000000000000000000\",\"code\":500}",
			"errorCode": "USER_OP_BUILD_FAILED",
			"inner_error": {
				"kind": {
					"body": "{\"error\":\"Internal server error\",\"cause\":\"Invalid estimation result: UserOperation reverted during simulation with reason: 0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000e4f6e6c7941676772656761746f72000000000000000000000000000000000000\",\"code\":500}"
				}
			}
		}
	}`

	json.Unmarshal([]byte(aggregatorErrorJSON), &errorData)

	decodedReason2 := engineService.ParseUserOpErrorJSON(errorData)
	fmt.Printf("Decoded error: %s\n", decodedReason2)
}
