package utils

import (
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"

	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jarcoal/httpmock"
	"github.com/stackup-wallet/stackup-bundler/pkg/userop"
	"github.com/stretchr/testify/assert"
)

func TestUserOp(t *testing.T) {

	t.Run("test getEndpoints", func(t *testing.T) {
		t.Run("when chainID is supported getEndpoints", func(t *testing.T) {
			bundlerID, paymaster, err := getEndpoints(1)
			assert.NoError(t, err)
			assert.NotEmpty(t, bundlerID, "bundlerID should not be empty")
			assert.NotEmpty(t, paymaster, "paymaster should not be empty")
		})

		t.Run("when chainID is not supported getEndpoints", func(t *testing.T) {
			bundlerID, paymaster, err := getEndpoints(1000)
			assert.Error(t, err)
			assert.Empty(t, bundlerID, "bundlerID should be empty")
			assert.Empty(t, paymaster, "paymaster should be empty")
		})

	})

	t.Run("test success SendUserOperation", func(t *testing.T) {
		// activate httpmock
		httpmock.Activate()
		defer httpmock.Deactivate()

		data := &userop.UserOperation{
			Sender:               common.Address{}, // Assuming common.Address has a zero value
			Nonce:                big.NewInt(12345),
			InitCode:             []byte{0x01, 0x02, 0x03}, // Example byte slice
			CallData:             []byte{0x04, 0x05, 0x06}, // Example byte slice
			CallGasLimit:         big.NewInt(67890),
			VerificationGasLimit: big.NewInt(111213),
			PreVerificationGas:   big.NewInt(141516),
			MaxFeePerGas:         big.NewInt(171819),
			MaxPriorityFeePerGas: big.NewInt(192021),
			PaymasterAndData:     []byte{0x22, 0x23, 0x24}, // Example byte slice
			Signature:            []byte{0x25, 0x26, 0x27}, // Example byte slice
		}

		// register mock response
		httpmock.RegisterResponder("POST", orderConf.BundlerUrlEthereum,
			func(r *http.Request) (*http.Response, error) {
				bytes, err := io.ReadAll(r.Body)
				if err != nil {
					log.Fatal(err)
				}

				if strings.Contains(string(bytes), "eth_sendUserOperation") {
					if orderConf.ActiveAAService == "biconomy" {
						assert.True(t, strings.Contains(string(bytes), "validation_and_execution"))
					} else {
						assert.False(t, strings.Contains(string(bytes), "validation_and_execution"))
					}
					resp, err := httpmock.NewJsonResponse(200, map[string]interface{}{
						"jsonrpc": "2.0",
						"id":      1,
						"result":  "0xa12db69d8d43384e9d9da5f0e9b9698c97c9a90c3447aa815d3f28daf21d3834",
					})
					return resp, err
				} else if strings.Contains(string(bytes), "eth_getUserOperationReceipt") {
					resp, err := httpmock.NewJsonResponse(200, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      1,
					"result": map[string]interface{}{
						"logs": []interface{}{
								map[string]interface{}{
									"topics": []interface{}{
										"0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f",
										"0x15178e60f1185869b7001608bc4f57ebd9064b77c7f8cc08db1da75464b535b3",
										"0x000000000000000000000000500081e858f7a214cfe4f729f0321ee0e24f900f",
										"0x00000000000000000000000000000f79b7faf42eebadba19acc07cd08af44789",
									},
									"blockNumber": "0x3494a41",
									"transactionHash": "0xd4c6ca8929833176505e4a1ee5693a5f5116415414ab672d0949bbd82df4ff54",
								},
							},
						"receipt": map[string]interface{}{
							"blockNumber":       "0x3494a41",
							"logs": []interface{}{
								map[string]interface{}{
									"address": "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789",
									"topics": []interface{}{
										"0x40ccd1ceb111a3c186ef9911e1b876dc1f789ed331b86097b3b8851055b6a137",
									},
									"data":             "0x0000000000000000000000000000000000000000000000000001c6bf526340008800aa2f3eb91b515b70ae1940b3ed9947d8fec227ac393d41e7be6c951626880000000000000000000000000000000000000000000000000000000000000679000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001584770777869632f3654654d58754f4b3766723171484c6f616936554a5168663744424b7949592f6744704c736a706d614e5a4e646e3059342b7561564d79414a554f466f4b4f7168424d7244555443756e47514a35412f6c554e726f415643575235444c31544b595a446d7279744c4f7a676a68642b69786e57557667394734654a43426c6e763473392f6f4575306d4d7a65644e53636d724b7273424f3977725275384b2f48466c69576765643334664a68343474484d6a6148753154324c765947646b754c53393647717244733471734b634c44466a47676267487962696a7351734d4b6646384a6c5369614f584156484e73756c2f554636644f5a7939784a39714156584a6a32577a367631416f48306137674d794e684f6c664b537667504a414d766a6d675741364d50524f74376e33564972644e743076535a58724244544441357354616439722b614f754b66357636513d3d0000000000000000",
									"blockNumber":      "0x3494a41",
									"transactionHash":  "0xd4c6ca8929833176505e4a1ee5693a5f5116415414ab672d0949bbd82df4ff54",
									"transactionIndex": "0x68",
									"blockHash":        "0x93412643414b664e4fd3467ff58c3bcbd6dc83b84080e1f044e7a16fcf015806",
								},
							},
							"logsBloom":         "0x000000000000010000000000000000000000000000000000000000000000020000090000000000040002001100400000001081000000000000000200000000000000000000000000000000280000008000080000000020000001000000000000000000000a000000000000000000280000000000080000408080001000080000004008000004000000000000000000020000000000000000000000000000000020000000000400000050...",
							"status":            "0x1",
							"to":                "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789",
							"transactionIndex":  "0x68",
							"type":              "0x2",
						},
					},
				})
				
				return resp, err
				}

				return httpmock.NewBytesResponse(200, []byte(`{"jsonrpc": "2.0","id": 1,"result":[]}`)), nil

			},
		)
		transactionHash, _, blockNumber, err := SendUserOperation(data, 1)
		assert.NoError(t, err)
		assert.NotEmpty(t, transactionHash, "transactionHash should not be empty")
		assert.Equal(t, int64(55134785), blockNumber)

	})

	t.Run("test success SponsorUserOperation", func(t *testing.T) {
		// activate httpmock
		httpmock.Activate()
		defer httpmock.Deactivate()

		data := &userop.UserOperation{
			Sender:               common.Address{}, // Assuming common.Address has a zero value
			Nonce:                big.NewInt(12345),
			InitCode:             []byte{0x01, 0x02, 0x03}, // Example byte slice
			CallData:             []byte{0x04, 0x05, 0x06}, // Example byte slice
			CallGasLimit:         big.NewInt(67890),
			VerificationGasLimit: big.NewInt(111213),
			PreVerificationGas:   big.NewInt(141516),
			MaxFeePerGas:         big.NewInt(171819),
			MaxPriorityFeePerGas: big.NewInt(192021),
			PaymasterAndData:     []byte{0x22, 0x23, 0x24}, // Example byte slice
			Signature:            []byte{0x25, 0x26, 0x27}, // Example byte slice
		}

		// register mock response
		httpmock.RegisterResponder("POST", orderConf.PaymasterUrlEthereum,
			func(r *http.Request) (*http.Response, error) {
				bytes, err := io.ReadAll(r.Body)
				if err != nil {
					log.Fatal(err)
				}

				if strings.Contains(string(bytes), "pm_sponsorUserOperation") {
					if orderConf.ActiveAAService == "biconomy" {
						assert.True(t, strings.Contains(string(bytes), "INFINITISM"))
						resp, err := httpmock.NewJsonResponse(200, map[string]interface{}{
							"jsonrpc": "2.0",
							"id":      1,
							"result": map[string]interface{}{
								"paymasterAndData":     "0x00000f79b7faf42eebadba19acc07cd08af447890000000000000000000...",
								"preVerificationGas":   "186034",
								"verificationGasLimit": 395693,
								"callGasLimit":         55412,
							},
						})
						return resp, err
					} else {
						assert.True(t, strings.Contains(string(bytes), "payg"))
						resp, err := httpmock.NewJsonResponse(200, map[string]interface{}{
							"jsonrpc": "2.0",
							"id":      1,
							"result": map[string]interface{}{
								"paymasterAndData":     "0x00000f79b7faf42eebadba19acc07cd08af447890000000000000000000...",
								"preVerificationGas":   "0x1234",
								"verificationGasLimit": "0x1234",
								"callGasLimit":         "0x1234",
							},
						})
						return resp, err
					}
				}
				return httpmock.NewBytesResponse(200, []byte(`{"jsonrpc": "2.0","id": 1,"result":[]}`)), nil

			},
		)

		err := SponsorUserOperation(data, "sponsored", "", 1)
		assert.NoError(t, err)
	})
}
