// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contracts

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// GatewaySettingManagerTokenFeeSettings is an auto generated low-level Go binding around an user-defined struct.
type GatewaySettingManagerTokenFeeSettings struct {
	SenderToProvider       *big.Int
	ProviderToAggregator   *big.Int
	SenderToAggregator     *big.Int
	ProviderToAggregatorFx *big.Int
}

// IGatewayOrder is an auto generated low-level Go binding around an user-defined struct.
type IGatewayOrder struct {
	Sender             common.Address
	Token              common.Address
	SenderFeeRecipient common.Address
	SenderFee          *big.Int
	ProtocolFee        *big.Int
	IsFulfilled        bool
	IsRefunded         bool
	RefundAddress      common.Address
	CurrentBPS         *big.Int
	Amount             *big.Int
}

// GatewayMetaData contains all meta data concerning the Gateway contract.
var GatewayMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"senderAmount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"aggregatorAmount\",\"type\":\"uint256\"}],\"name\":\"FxTransferFeeSplit\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint8\",\"name\":\"version\",\"type\":\"uint8\"}],\"name\":\"Initialized\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"senderAmount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"providerAmount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"aggregatorAmount\",\"type\":\"uint256\"}],\"name\":\"LocalTransferFeeSplit\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"token\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"protocolFee\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"rate\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"string\",\"name\":\"messageHash\",\"type\":\"string\"}],\"name\":\"OrderCreated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"fee\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"}],\"name\":\"OrderRefunded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferStarted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferred\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"Paused\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"what\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"treasuryAddress\",\"type\":\"address\"}],\"name\":\"ProtocolAddressUpdated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"SenderFeeTransferred\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"treasuryAddress\",\"type\":\"address\"}],\"name\":\"SetFeeRecipient\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"what\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"value\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"status\",\"type\":\"uint256\"}],\"name\":\"SettingManagerBool\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"liquidityProvider\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"token\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"aggregatorFee\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint96\",\"name\":\"rate\",\"type\":\"uint96\"}],\"name\":\"SettleIn\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"splitOrderId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"liquidityProvider\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint64\",\"name\":\"settlePercent\",\"type\":\"uint64\"},{\"indexed\":false,\"internalType\":\"uint64\",\"name\":\"rebatePercent\",\"type\":\"uint64\"}],\"name\":\"SettleOut\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"token\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"senderToProvider\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"providerToAggregator\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"senderToAggregator\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"providerToAggregatorFx\",\"type\":\"uint256\"}],\"name\":\"TokenFeeSettingsUpdated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"Unpaused\",\"type\":\"event\"},{\"inputs\":[],\"name\":\"acceptOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_token\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_amount\",\"type\":\"uint256\"},{\"internalType\":\"uint96\",\"name\":\"_rate\",\"type\":\"uint96\"},{\"internalType\":\"address\",\"name\":\"_senderFeeRecipient\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_senderFee\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"_refundAddress\",\"type\":\"address\"},{\"internalType\":\"string\",\"name\":\"messageHash\",\"type\":\"string\"}],\"name\":\"createOrder\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getAggregator\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"_orderId\",\"type\":\"bytes32\"}],\"name\":\"getOrderInfo\",\"outputs\":[{\"components\":[{\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"token\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"senderFeeRecipient\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"senderFee\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"protocolFee\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"isFulfilled\",\"type\":\"bool\"},{\"internalType\":\"bool\",\"name\":\"isRefunded\",\"type\":\"bool\"},{\"internalType\":\"address\",\"name\":\"refundAddress\",\"type\":\"address\"},{\"internalType\":\"uint96\",\"name\":\"currentBPS\",\"type\":\"uint96\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"internalType\":\"structIGateway.Order\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"token\",\"type\":\"address\"}],\"name\":\"getTokenFeeSettings\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"senderToProvider\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"providerToAggregator\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"senderToAggregator\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"providerToAggregatorFx\",\"type\":\"uint256\"}],\"internalType\":\"structGatewaySettingManager.TokenFeeSettings\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"initialize\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_token\",\"type\":\"address\"}],\"name\":\"isTokenSupported\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"pause\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"paused\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"pendingOwner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_fee\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"_orderId\",\"type\":\"bytes32\"}],\"name\":\"refund\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"renounceOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"token\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"senderToProvider\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"providerToAggregator\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"senderToAggregator\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"providerToAggregatorFx\",\"type\":\"uint256\"}],\"name\":\"setTokenFeeSettings\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"what\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"value\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"status\",\"type\":\"uint256\"}],\"name\":\"settingManagerBool\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"_orderId\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"_token\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_amount\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"_senderFeeRecipient\",\"type\":\"address\"},{\"internalType\":\"uint96\",\"name\":\"_senderFee\",\"type\":\"uint96\"},{\"internalType\":\"address\",\"name\":\"_recipient\",\"type\":\"address\"},{\"internalType\":\"uint96\",\"name\":\"_rate\",\"type\":\"uint96\"}],\"name\":\"settleIn\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"_splitOrderId\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"_orderId\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"_liquidityProvider\",\"type\":\"address\"},{\"internalType\":\"uint64\",\"name\":\"_settlePercent\",\"type\":\"uint64\"},{\"internalType\":\"uint64\",\"name\":\"_rebatePercent\",\"type\":\"uint64\"}],\"name\":\"settleOut\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"unpause\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"what\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"value\",\"type\":\"address\"}],\"name\":\"updateProtocolAddress\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Bin: "0x608060405234801561000f575f5ffd5b5061001e61002360201b60201c565b6101b3565b5f60019054906101000a900460ff1615610072576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161006990610161565b60405180910390fd5b60ff80165f5f9054906101000a900460ff1660ff16146100df5760ff5f5f6101000a81548160ff021916908360ff1602179055507f7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb384740249860ff6040516100d6919061019a565b60405180910390a15b565b5f82825260208201905092915050565b7f496e697469616c697a61626c653a20636f6e747261637420697320696e6974695f8201527f616c697a696e6700000000000000000000000000000000000000000000000000602082015250565b5f61014b6027836100e1565b9150610156826100f1565b604082019050919050565b5f6020820190508181035f8301526101788161013f565b9050919050565b5f60ff82169050919050565b6101948161017f565b82525050565b5f6020820190506101ad5f83018461018b565b92915050565b6150aa806101c05f395ff3fe608060405234801561000f575f5ffd5b506004361061012a575f3560e01c8063809804f7116100ab5780638da5cb5b1161006f5780638da5cb5b146102f4578063cd99240014610312578063d839de631461032e578063e30c39781461035e578063f2fde38b1461037c5761012a565b8063809804f7146102645780638129fc1c146102945780638456cb591461029e578063898861b0146102a85780638bfa0549146102c45761012a565b8063715018a6116100f2578063715018a6146101c057806371eedb88146101ca57806375151b63146101fa578063768c6ec01461022a57806379ba50971461025a5761012a565b806332553efa1461012e5780633ad59dbc1461015e5780633f4ba83a1461017c57806340ebc677146101865780635c975abb146101a2575b5f5ffd5b61014860048036038101906101439190613769565b610398565b60405161015591906137fa565b60405180910390f35b610166610b21565b6040516101739190613822565b60405180910390f35b610184610b49565b005b6101a0600480360381019061019b919061383b565b610b5b565b005b6101aa610e1f565b6040516101b791906137fa565b60405180910390f35b6101c8610e34565b005b6101e460048036038101906101df91906138ac565b610e47565b6040516101f191906137fa565b60405180910390f35b610214600480360381019061020f91906138ea565b6112a2565b60405161022191906137fa565b60405180910390f35b610244600480360381019061023f9190613915565b6112fa565b6040516102519190613a5d565b60405180910390f35b61026261150a565b005b61027e60048036038101906102799190613b02565b611596565b60405161028b9190613bce565b60405180910390f35b61029c611c1d565b005b6102a6611d69565b005b6102c260048036038101906102bd9190613be7565b611d7b565b005b6102de60048036038101906102d991906138ea565b611ff9565b6040516102eb9190613cb1565b60405180910390f35b6102fc612077565b6040516103099190613822565b60405180910390f35b61032c60048036038101906103279190613cca565b61209f565b005b61034860048036038101906103439190613d1a565b612221565b60405161035591906137fa565b60405180910390f35b61036661287c565b6040516103739190613822565b60405180910390f35b610396600480360381019061039191906138ea565b6128a4565b005b5f60995f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610428576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161041f90613e11565b60405180910390fd5b60ff5f8681526020019081526020015f206005015f9054906101000a900460ff1615610489576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161048090613e79565b60405180910390fd5b60ff5f8681526020019081526020015f2060050160019054906101000a900460ff16156104eb576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104e290613ee1565b60405180910390fd5b6097548267ffffffffffffffff16111561053a576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161053190613f49565b60405180910390fd5b5f60ff5f8781526020019081526020015f206001015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690505f60ff5f8881526020019081526020015f206006015f9054906101000a90046bffffffffffffffffffffffff166bffffffffffffffffffffffff1690505f8567ffffffffffffffff161180156105d15750808567ffffffffffffffff1611155b610610576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161060790613fb1565b60405180910390fd5b8467ffffffffffffffff1660ff5f8981526020019081526020015f206006015f8282829054906101000a90046bffffffffffffffffffffffff166106549190613ffc565b92506101000a8154816bffffffffffffffffffffffff02191690836bffffffffffffffffffffffff1602179055505f60ff5f8981526020019081526020015f206006015f9054906101000a90046bffffffffffffffffffffffff166bffffffffffffffffffffffff160361078057600160ff5f8981526020019081526020015f206005015f6101000a81548160ff0219169083151502179055505f60ff5f8981526020019081526020015f20600301541415801561072657505f60ff5f8981526020019081526020015f206004015414155b1561077f5761077e878360ff5f8b81526020019081526020015f206002015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1660ff5f8c81526020019081526020015f2060030154612950565b5b5b5f60ff5f8981526020019081526020015f2060030154141580156107b757505f60ff5f8981526020019081526020015f2060040154145b156107fc576107fb878760ff5f8b81526020019081526020015f206002015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1688612bb2565b5b5f818667ffffffffffffffff1660ff5f8b81526020019081526020015f2060070154610828919061403b565b61083291906140a9565b90508060ff5f8a81526020019081526020015f206007015f82825461085791906140d9565b925050819055505f60ff5f8a81526020019081526020015f206004015414610a42575f609b5f60ff5f8c81526020019081526020015f206001015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f206040518060800160405290815f8201548152602001600182015481526020016002820154815260200160038201548152505090505f609754826060015184610932919061403b565b61093c91906140a9565b9050808361094a91906140d9565b92505f8767ffffffffffffffff16146109a1575f6097548867ffffffffffffffff1683610977919061403b565b61098191906140a9565b9050808261098f91906140d9565b9150808461099d919061410c565b9350505b8473ffffffffffffffffffffffffffffffffffffffff1663a9059cbb609860089054906101000a900473ffffffffffffffffffffffffffffffffffffffff16836040518363ffffffff1660e01b81526004016109fe92919061414e565b6020604051808303815f875af1158015610a1a573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190610a3e919061419f565b5050505b8273ffffffffffffffffffffffffffffffffffffffff1663a9059cbb88836040518363ffffffff1660e01b8152600401610a7d92919061414e565b6020604051808303815f875af1158015610a99573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190610abd919061419f565b508673ffffffffffffffffffffffffffffffffffffffff16887f1e4a1a8ad772d3f0dbb387879bc5e8faadf16e0513bf77d50620741ab92b4c458b8989604051610b09939291906141d9565b60405180910390a36001935050505095945050505050565b5f60995f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b610b51612faa565b610b59613028565b565b610b63612faa565b5f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1603610bd1576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610bc890614258565b60405180910390fd5b5f7f74726561737572790000000000000000000000000000000000000000000000008303610cd3578173ffffffffffffffffffffffffffffffffffffffff16609860089054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1603610c89576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610c80906142e6565b60405180910390fd5b81609860086101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060019050610dcf565b7f61676772656761746f72000000000000000000000000000000000000000000008303610dce578173ffffffffffffffffffffffffffffffffffffffff1660995f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1603610d89576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610d8090614374565b60405180910390fd5b8160995f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550600190505b5b8015610e1a578173ffffffffffffffffffffffffffffffffffffffff16837fbbc5b96e57cfecb3dbeeadf92e87f15e58e64fcd75cbe256dcc5d9ef2e51e8a460405160405180910390a35b505050565b5f60cd5f9054906101000a900460ff16905090565b610e3c612faa565b610e455f613089565b565b5f60995f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610ed7576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610ece90613e11565b60405180910390fd5b60ff5f8381526020019081526020015f206005015f9054906101000a900460ff1615610f38576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610f2f90613e79565b60405180910390fd5b60ff5f8381526020019081526020015f2060050160019054906101000a900460ff1615610f9a576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610f9190613ee1565b60405180910390fd5b8260ff5f8481526020019081526020015f20600401541015610ff1576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610fe8906143dc565b60405180910390fd5b5f8311156110cb5760ff5f8381526020019081526020015f206001015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1663a9059cbb609860089054906101000a900473ffffffffffffffffffffffffffffffffffffffff16856040518363ffffffff1660e01b815260040161108992919061414e565b6020604051808303815f875af11580156110a5573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906110c9919061419f565b505b600160ff5f8481526020019081526020015f2060050160016101000a81548160ff0219169083151502179055505f60ff5f8481526020019081526020015f206006015f6101000a8154816bffffffffffffffffffffffff02191690836bffffffffffffffffffffffff1602179055505f8360ff5f8581526020019081526020015f206007015461115b91906140d9565b905060ff5f8481526020019081526020015f206001015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1663a9059cbb60ff5f8681526020019081526020015f2060050160029054906101000a900473ffffffffffffffffffffffffffffffffffffffff1660ff5f8781526020019081526020015f206003015484611201919061410c565b6040518363ffffffff1660e01b815260040161121e92919061414e565b6020604051808303815f875af115801561123a573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061125e919061419f565b50827f0736fe428e1747ca8d387c2e6fa1a31a0cde62d3a167c40a46ade59a3cdc828e8560405161128f91906143fa565b60405180910390a2600191505092915050565b5f6001609a5f8473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f2054036112f157600190506112f5565b5f90505b919050565b6113026135c0565b60ff5f8381526020019081526020015f20604051806101400160405290815f82015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001600182015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001600282015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020016003820154815260200160048201548152602001600582015f9054906101000a900460ff161515151581526020016005820160019054906101000a900460ff161515151581526020016005820160029054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001600682015f9054906101000a90046bffffffffffffffffffffffff166bffffffffffffffffffffffff166bffffffffffffffffffffffff1681526020016007820154815250509050919050565b5f6115136130b9565b90508073ffffffffffffffffffffffffffffffffffffffff1661153461287c565b73ffffffffffffffffffffffffffffffffffffffff161461158a576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161158190614483565b60405180910390fd5b61159381613089565b50565b5f61159f6130c0565b6115ac898986898961310a565b5f83839050036115f1576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016115e8906144eb565b60405180910390fd5b8873ffffffffffffffffffffffffffffffffffffffff166323b872dd3330888c61161b919061410c565b6040518463ffffffff1660e01b815260040161163993929190614509565b6020604051808303815f875af1158015611655573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190611679919061419f565b506101005f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8154809291906116c89061453e565b9190505550336101005f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20544660405160200161172093929190614585565b6040516020818303038152906040528051906020012090505f73ffffffffffffffffffffffffffffffffffffffff1660ff5f8381526020019081526020015f205f015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16146117d8576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016117cf90614604565b60405180910390fd5b5f6064886bffffffffffffffffffffffff1603611839575f90505f8611611834576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161182b9061466c565b60405180910390fd5b611912565b5f609b5f8c73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f206040518060800160405290815f8201548152602001600182015481526020016002820154815260200160038201548152505090505f8160600151116118f1576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016118e8906146d4565b60405180910390fd5b60975481606001518b611904919061403b565b61190e91906140a9565b9150505b6040518061014001604052803373ffffffffffffffffffffffffffffffffffffffff1681526020018b73ffffffffffffffffffffffffffffffffffffffff1681526020018873ffffffffffffffffffffffffffffffffffffffff1681526020018781526020018281526020015f151581526020015f151581526020018673ffffffffffffffffffffffffffffffffffffffff16815260200160975467ffffffffffffffff166bffffffffffffffffffffffff1681526020018a81525060ff5f8481526020019081526020015f205f820151815f015f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506020820151816001015f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506040820151816002015f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550606082015181600301556080820151816004015560a0820151816005015f6101000a81548160ff02191690831515021790555060c08201518160050160016101000a81548160ff02191690831515021790555060e08201518160050160026101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610100820151816006015f6101000a8154816bffffffffffffffffffffffff02191690836bffffffffffffffffffffffff160217905550610120820151816007015590505060ff5f8381526020019081526020015f20600701548a73ffffffffffffffffffffffffffffffffffffffff168673ffffffffffffffffffffffffffffffffffffffff167f40ccd1ceb111a3c186ef9911e1b876dc1f789ed331b86097b3b8851055b6a13784868d8a8a604051611c08959493929190614775565b60405180910390a45098975050505050505050565b5f5f60019054906101000a900460ff16159050808015611c4d575060015f5f9054906101000a900460ff1660ff16105b80611c7a5750611c5c306132b7565b158015611c79575060015f5f9054906101000a900460ff1660ff16145b5b611cb9576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401611cb090614831565b60405180910390fd5b60015f5f6101000a81548160ff021916908360ff1602179055508015611cf45760015f60016101000a81548160ff0219169083151502179055505b620186a0609781905550611d066132d9565b611d0e613331565b8015611d66575f5f60016101000a81548160ff0219169083151502179055507f7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb38474024986001604051611d5d9190614894565b60405180910390a15b50565b611d71612faa565b611d79613389565b565b611d83612faa565b6001609a5f8773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205414611e03576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401611dfa906148f7565b60405180910390fd5b609754841115611e48576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401611e3f90614985565b60405180910390fd5b609754831115611e8d576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401611e8490614a13565b60405180910390fd5b609754821115611ed2576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401611ec990614aa1565b60405180910390fd5b609754811115611f17576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401611f0e90614b2f565b60405180910390fd5b604051806080016040528085815260200184815260200183815260200182815250609b5f8773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f820151815f01556020820151816001015560408201518160020155606082015181600301559050508473ffffffffffffffffffffffffffffffffffffffff167fd4d646cffa66ebf695b792bd660c97076ed45a889e14d544eb8ab8a44b34a59c85858585604051611fea9493929190614b4d565b60405180910390a25050505050565b612001613673565b609b5f8373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f206040518060800160405290815f820154815260200160018201548152602001600282015481526020016003820154815250509050919050565b5f60335f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b6120a7612faa565b5f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603612115576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161210c90614258565b60405180910390fd5b60018114806121245750600281145b612163576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161215a90614bda565b60405180910390fd5b7f746f6b656e000000000000000000000000000000000000000000000000000000830361221c5780609a5f8473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20819055508173ffffffffffffffffffffffffffffffffffffffff16837fcfa976492af7c14a916cc3a239f4c9c75bbd7f5f0e398beb41d892c7eeccae4c8360405161221391906143fa565b60405180910390a35b505050565b5f61222a6130c0565b5f73ffffffffffffffffffffffffffffffffffffffff1660ff5f8a81526020019081526020015f205f015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16146122ca576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016122c190614604565b60405180910390fd5b609754861161230e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161230590614c42565b60405180910390fd5b61232987878588886bffffffffffffffffffffffff1661310a565b8673ffffffffffffffffffffffffffffffffffffffff166323b872dd3330876bffffffffffffffffffffffff168a612361919061410c565b6040518463ffffffff1660e01b815260040161237f93929190614509565b6020604051808303815f875af115801561239b573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906123bf919061419f565b505f8690505f6064846bffffffffffffffffffffffff1603612430575f866bffffffffffffffffffffffff161161242b576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016124229061466c565b60405180910390fd5b6125be565b5f609b5f8b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f206040518060800160405290815f8201548152602001600182015481526020016002820154815260200160038201548152505090505f8160600151116124e8576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016124df906146d4565b60405180910390fd5b60975481606001518a6124fb919061403b565b61250591906140a9565b91505f8211156125bc57818361251b91906140d9565b92508973ffffffffffffffffffffffffffffffffffffffff1663a9059cbb609860089054906101000a900473ffffffffffffffffffffffffffffffffffffffff16846040518363ffffffff1660e01b815260040161257a92919061414e565b6020604051808303815f875af1158015612596573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906125ba919061419f565b505b505b8460ff5f8c81526020019081526020015f205f015f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508860ff5f8c81526020019081526020015f206001015f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508660ff5f8c81526020019081526020015f206002015f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550856bffffffffffffffffffffffff1660ff5f8c81526020019081526020015f20600301819055508060ff5f8c81526020019081526020015f2060040181905550600160ff5f8c81526020019081526020015f206005015f6101000a81548160ff0219169083151502179055508160ff5f8c81526020019081526020015f20600701819055508873ffffffffffffffffffffffffffffffffffffffff1663a9059cbb86846040518363ffffffff1660e01b815260040161277392919061414e565b6020604051808303815f875af115801561278f573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906127b3919061419f565b505f866bffffffffffffffffffffffff16146127ff575f81036127e3576127de8a3389609754612bb2565b6127fe565b6127fd8a8a89896bffffffffffffffffffffffff16612950565b5b5b8473ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff168b7fb5273ccce1412b056c9246e834895f9d717974c505f8e5a6c7d08cd0300a066b858d868a6040516128639493929190614c6f565b60405180910390a4600192505050979650505050505050565b5f60655f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b6128ac612faa565b8060655f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508073ffffffffffffffffffffffffffffffffffffffff1661290b612077565b73ffffffffffffffffffffffffffffffffffffffff167f38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e2270060405160405180910390a350565b5f609b5f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f206040518060800160405290815f8201548152602001600182015481526020016002820154815260200160038201548152505090505f60975482604001516097546129d891906140d9565b846129e3919061403b565b6129ed91906140a9565b90505f81846129fc91906140d9565b90505f821115612a83578573ffffffffffffffffffffffffffffffffffffffff1663a9059cbb86846040518363ffffffff1660e01b8152600401612a4192919061414e565b6020604051808303815f875af1158015612a5d573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190612a81919061419f565b505b5f811115612b2a578573ffffffffffffffffffffffffffffffffffffffff1663a9059cbb609860089054906101000a900473ffffffffffffffffffffffffffffffffffffffff16836040518363ffffffff1660e01b8152600401612ae892919061414e565b6020604051808303815f875af1158015612b04573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190612b28919061419f565b505b818573ffffffffffffffffffffffffffffffffffffffff16887f879f6eb4f1506eb3029982039d90b0e82b07d54f5e911a3c644a974863a98a6c60405160405180910390a4867f88592047496a7850992dc5e8cd92a9b633cef0d191a4f5e87fd745c7d382630a8383604051612ba1929190614cb2565b60405180910390a250505050505050565b5f609b5f60ff5f8881526020019081526020015f206001015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f206040518060800160405290815f8201548152602001600182015481526020016002820154815260200160038201548152505090505f60ff5f8781526020019081526020015f206003015490505f60ff5f8881526020019081526020015f206001015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690505f609754845f015184612cb9919061403b565b612cc391906140a9565b90505f6097548667ffffffffffffffff1683612cdf919061403b565b612ce991906140a9565b90505f609754866020015183612cff919061403b565b612d0991906140a9565b90505f8386612d1891906140d9565b90505f8114158015612d6257505f60ff5f8d81526020019081526020015f206006015f9054906101000a90046bffffffffffffffffffffffff166bffffffffffffffffffffffff16145b15612de4578473ffffffffffffffffffffffffffffffffffffffff1663a9059cbb8a836040518363ffffffff1660e01b8152600401612da292919061414e565b6020604051808303815f875af1158015612dbe573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190612de2919061419f565b505b5f8214612e8a578473ffffffffffffffffffffffffffffffffffffffff1663a9059cbb609860089054906101000a900473ffffffffffffffffffffffffffffffffffffffff16846040518363ffffffff1660e01b8152600401612e4892919061414e565b6020604051808303815f875af1158015612e64573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190612e88919061419f565b505b8183612e9691906140d9565b92505f8314612f1c578473ffffffffffffffffffffffffffffffffffffffff1663a9059cbb8b856040518363ffffffff1660e01b8152600401612eda92919061414e565b6020604051808303815f875af1158015612ef6573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190612f1a919061419f565b505b808973ffffffffffffffffffffffffffffffffffffffff168c7f879f6eb4f1506eb3029982039d90b0e82b07d54f5e911a3c644a974863a98a6c60405160405180910390a48a7f831c7cc0006d91462607c476603366c48469d125de6228c0791a7090efd7f7a4828585604051612f9593929190614cd9565b60405180910390a25050505050505050505050565b612fb26130b9565b73ffffffffffffffffffffffffffffffffffffffff16612fd0612077565b73ffffffffffffffffffffffffffffffffffffffff1614613026576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161301d90614d58565b60405180910390fd5b565b6130306133eb565b5f60cd5f6101000a81548160ff0219169083151502179055507f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa6130726130b9565b60405161307f9190613822565b60405180910390a1565b60655f6101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556130b681613434565b50565b5f33905090565b6130c8610e1f565b15613108576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016130ff90614dc0565b60405180910390fd5b565b6001609a5f8773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20541461318a576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161318190614e28565b60405180910390fd5b5f84036131cc576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016131c390614e90565b60405180910390fd5b5f73ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff160361323a576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161323190614ef8565b60405180910390fd5b5f81146132b0575f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16036132af576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016132a690614f60565b60405180910390fd5b5b5050505050565b5f5f8273ffffffffffffffffffffffffffffffffffffffff163b119050919050565b5f60019054906101000a900460ff16613327576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161331e90614fee565b60405180910390fd5b61332f6134f7565b565b5f60019054906101000a900460ff1661337f576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161337690614fee565b60405180910390fd5b613387613557565b565b6133916130c0565b600160cd5f6101000a81548160ff0219169083151502179055507f62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a2586133d46130b9565b6040516133e19190613822565b60405180910390a1565b6133f3610e1f565b613432576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161342990615056565b60405180910390fd5b565b5f60335f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690508160335f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b5f60019054906101000a900460ff16613545576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161353c90614fee565b60405180910390fd5b6135556135506130b9565b613089565b565b5f60019054906101000a900460ff166135a5576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161359c90614fee565b60405180910390fd5b5f60cd5f6101000a81548160ff021916908315150217905550565b6040518061014001604052805f73ffffffffffffffffffffffffffffffffffffffff1681526020015f73ffffffffffffffffffffffffffffffffffffffff1681526020015f73ffffffffffffffffffffffffffffffffffffffff1681526020015f81526020015f81526020015f151581526020015f151581526020015f73ffffffffffffffffffffffffffffffffffffffff1681526020015f6bffffffffffffffffffffffff1681526020015f81525090565b60405180608001604052805f81526020015f81526020015f81526020015f81525090565b5f5ffd5b5f5ffd5b5f819050919050565b6136b18161369f565b81146136bb575f5ffd5b50565b5f813590506136cc816136a8565b92915050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6136fb826136d2565b9050919050565b61370b816136f1565b8114613715575f5ffd5b50565b5f8135905061372681613702565b92915050565b5f67ffffffffffffffff82169050919050565b6137488161372c565b8114613752575f5ffd5b50565b5f813590506137638161373f565b92915050565b5f5f5f5f5f60a0868803121561378257613781613697565b5b5f61378f888289016136be565b95505060206137a0888289016136be565b94505060406137b188828901613718565b93505060606137c288828901613755565b92505060806137d388828901613755565b9150509295509295909350565b5f8115159050919050565b6137f4816137e0565b82525050565b5f60208201905061380d5f8301846137eb565b92915050565b61381c816136f1565b82525050565b5f6020820190506138355f830184613813565b92915050565b5f5f6040838503121561385157613850613697565b5b5f61385e858286016136be565b925050602061386f85828601613718565b9150509250929050565b5f819050919050565b61388b81613879565b8114613895575f5ffd5b50565b5f813590506138a681613882565b92915050565b5f5f604083850312156138c2576138c1613697565b5b5f6138cf85828601613898565b92505060206138e0858286016136be565b9150509250929050565b5f602082840312156138ff576138fe613697565b5b5f61390c84828501613718565b91505092915050565b5f6020828403121561392a57613929613697565b5b5f613937848285016136be565b91505092915050565b613949816136f1565b82525050565b61395881613879565b82525050565b613967816137e0565b82525050565b5f6bffffffffffffffffffffffff82169050919050565b61398d8161396d565b82525050565b61014082015f8201516139a85f850182613940565b5060208201516139bb6020850182613940565b5060408201516139ce6040850182613940565b5060608201516139e1606085018261394f565b5060808201516139f4608085018261394f565b5060a0820151613a0760a085018261395e565b5060c0820151613a1a60c085018261395e565b5060e0820151613a2d60e0850182613940565b50610100820151613a42610100850182613984565b50610120820151613a5761012085018261394f565b50505050565b5f61014082019050613a715f830184613993565b92915050565b613a808161396d565b8114613a8a575f5ffd5b50565b5f81359050613a9b81613a77565b92915050565b5f5ffd5b5f5ffd5b5f5ffd5b5f5f83601f840112613ac257613ac1613aa1565b5b8235905067ffffffffffffffff811115613adf57613ade613aa5565b5b602083019150836001820283011115613afb57613afa613aa9565b5b9250929050565b5f5f5f5f5f5f5f5f60e0898b031215613b1e57613b1d613697565b5b5f613b2b8b828c01613718565b9850506020613b3c8b828c01613898565b9750506040613b4d8b828c01613a8d565b9650506060613b5e8b828c01613718565b9550506080613b6f8b828c01613898565b94505060a0613b808b828c01613718565b93505060c089013567ffffffffffffffff811115613ba157613ba061369b565b5b613bad8b828c01613aad565b92509250509295985092959890939650565b613bc88161369f565b82525050565b5f602082019050613be15f830184613bbf565b92915050565b5f5f5f5f5f60a08688031215613c0057613bff613697565b5b5f613c0d88828901613718565b9550506020613c1e88828901613898565b9450506040613c2f88828901613898565b9350506060613c4088828901613898565b9250506080613c5188828901613898565b9150509295509295909350565b608082015f820151613c725f85018261394f565b506020820151613c85602085018261394f565b506040820151613c98604085018261394f565b506060820151613cab606085018261394f565b50505050565b5f608082019050613cc45f830184613c5e565b92915050565b5f5f5f60608486031215613ce157613ce0613697565b5b5f613cee868287016136be565b9350506020613cff86828701613718565b9250506040613d1086828701613898565b9150509250925092565b5f5f5f5f5f5f5f60e0888a031215613d3557613d34613697565b5b5f613d428a828b016136be565b9750506020613d538a828b01613718565b9650506040613d648a828b01613898565b9550506060613d758a828b01613718565b9450506080613d868a828b01613a8d565b93505060a0613d978a828b01613718565b92505060c0613da88a828b01613a8d565b91505092959891949750929550565b5f82825260208201905092915050565b7f4f6e6c7941676772656761746f720000000000000000000000000000000000005f82015250565b5f613dfb600e83613db7565b9150613e0682613dc7565b602082019050919050565b5f6020820190508181035f830152613e2881613def565b9050919050565b7f4f7264657246756c66696c6c65640000000000000000000000000000000000005f82015250565b5f613e63600e83613db7565b9150613e6e82613e2f565b602082019050919050565b5f6020820190508181035f830152613e9081613e57565b9050919050565b7f4f72646572526566756e646564000000000000000000000000000000000000005f82015250565b5f613ecb600d83613db7565b9150613ed682613e97565b602082019050919050565b5f6020820190508181035f830152613ef881613ebf565b9050919050565b7f496e76616c696452656261746550657263656e740000000000000000000000005f82015250565b5f613f33601483613db7565b9150613f3e82613eff565b602082019050919050565b5f6020820190508181035f830152613f6081613f27565b9050919050565b7f496e76616c6964536574746c6550657263656e740000000000000000000000005f82015250565b5f613f9b601483613db7565b9150613fa682613f67565b602082019050919050565b5f6020820190508181035f830152613fc881613f8f565b9050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6140068261396d565b91506140118361396d565b925082820390506bffffffffffffffffffffffff81111561403557614034613fcf565b5b92915050565b5f61404582613879565b915061405083613879565b925082820261405e81613879565b9150828204841483151761407557614074613fcf565b5b5092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f6140b382613879565b91506140be83613879565b9250826140ce576140cd61407c565b5b828204905092915050565b5f6140e382613879565b91506140ee83613879565b925082820390508181111561410657614105613fcf565b5b92915050565b5f61411682613879565b915061412183613879565b925082820190508082111561413957614138613fcf565b5b92915050565b61414881613879565b82525050565b5f6040820190506141615f830185613813565b61416e602083018461413f565b9392505050565b61417e816137e0565b8114614188575f5ffd5b50565b5f8151905061419981614175565b92915050565b5f602082840312156141b4576141b3613697565b5b5f6141c18482850161418b565b91505092915050565b6141d38161372c565b82525050565b5f6060820190506141ec5f830186613bbf565b6141f960208301856141ca565b61420660408301846141ca565b949350505050565b7f476174657761793a207a65726f206164647265737300000000000000000000005f82015250565b5f614242601583613db7565b915061424d8261420e565b602082019050919050565b5f6020820190508181035f83015261426f81614236565b9050919050565b7f476174657761793a207472656173757279206164647265737320616c726561645f8201527f7920736574000000000000000000000000000000000000000000000000000000602082015250565b5f6142d0602583613db7565b91506142db82614276565b604082019050919050565b5f6020820190508181035f8301526142fd816142c4565b9050919050565b7f476174657761793a2061676772656761746f72206164647265737320616c72655f8201527f6164792073657400000000000000000000000000000000000000000000000000602082015250565b5f61435e602783613db7565b915061436982614304565b604082019050919050565b5f6020820190508181035f83015261438b81614352565b9050919050565b7f4665654578636565647350726f746f636f6c46656500000000000000000000005f82015250565b5f6143c6601583613db7565b91506143d182614392565b602082019050919050565b5f6020820190508181035f8301526143f3816143ba565b9050919050565b5f60208201905061440d5f83018461413f565b92915050565b7f4f776e61626c6532537465703a2063616c6c6572206973206e6f7420746865205f8201527f6e6577206f776e65720000000000000000000000000000000000000000000000602082015250565b5f61446d602983613db7565b915061447882614413565b604082019050919050565b5f6020820190508181035f83015261449a81614461565b9050919050565b7f496e76616c69644d6573736167654861736800000000000000000000000000005f82015250565b5f6144d5601283613db7565b91506144e0826144a1565b602082019050919050565b5f6020820190508181035f830152614502816144c9565b9050919050565b5f60608201905061451c5f830186613813565b6145296020830185613813565b614536604083018461413f565b949350505050565b5f61454882613879565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff820361457a57614579613fcf565b5b600182019050919050565b5f6060820190506145985f830186613813565b6145a5602083018561413f565b6145b2604083018461413f565b949350505050565b7f4f72646572416c726561647945786973747300000000000000000000000000005f82015250565b5f6145ee601283613db7565b91506145f9826145ba565b602082019050919050565b5f6020820190508181035f83015261461b816145e2565b9050919050565b7f53656e64657246656549735a65726f00000000000000000000000000000000005f82015250565b5f614656600f83613db7565b915061466182614622565b602082019050919050565b5f6020820190508181035f8301526146838161464a565b9050919050565b7f546f6b656e46656553657474696e67734e6f74436f6e666967757265640000005f82015250565b5f6146be601d83613db7565b91506146c98261468a565b602082019050919050565b5f6020820190508181035f8301526146eb816146b2565b9050919050565b5f819050919050565b5f61471561471061470b8461396d565b6146f2565b613879565b9050919050565b614725816146fb565b82525050565b828183375f83830152505050565b5f601f19601f8301169050919050565b5f6147548385613db7565b935061476183858461472b565b61476a83614739565b840190509392505050565b5f6080820190506147885f83018861413f565b6147956020830187613bbf565b6147a2604083018661471c565b81810360608301526147b5818486614749565b90509695505050505050565b7f496e697469616c697a61626c653a20636f6e747261637420697320616c7265615f8201527f647920696e697469616c697a6564000000000000000000000000000000000000602082015250565b5f61481b602e83613db7565b9150614826826147c1565b604082019050919050565b5f6020820190508181035f8301526148488161480f565b9050919050565b5f819050919050565b5f60ff82169050919050565b5f61487e6148796148748461484f565b6146f2565b614858565b9050919050565b61488e81614864565b82525050565b5f6020820190506148a75f830184614885565b92915050565b7f476174657761793a20746f6b656e206e6f7420737570706f72746564000000005f82015250565b5f6148e1601c83613db7565b91506148ec826148ad565b602082019050919050565b5f6020820190508181035f83015261490e816148d5565b9050919050565b7f476174657761793a20696e76616c69642073656e64657220746f2070726f76695f8201527f6465720000000000000000000000000000000000000000000000000000000000602082015250565b5f61496f602383613db7565b915061497a82614915565b604082019050919050565b5f6020820190508181035f83015261499c81614963565b9050919050565b7f476174657761793a20696e76616c69642070726f766964657220746f206167675f8201527f72656761746f7200000000000000000000000000000000000000000000000000602082015250565b5f6149fd602783613db7565b9150614a08826149a3565b604082019050919050565b5f6020820190508181035f830152614a2a816149f1565b9050919050565b7f476174657761793a20696e76616c69642073656e64657220746f2061676772655f8201527f6761746f72000000000000000000000000000000000000000000000000000000602082015250565b5f614a8b602583613db7565b9150614a9682614a31565b604082019050919050565b5f6020820190508181035f830152614ab881614a7f565b9050919050565b7f476174657761793a20696e76616c69642070726f766964657220746f206167675f8201527f72656761746f7220667800000000000000000000000000000000000000000000602082015250565b5f614b19602a83613db7565b9150614b2482614abf565b604082019050919050565b5f6020820190508181035f830152614b4681614b0d565b9050919050565b5f608082019050614b605f83018761413f565b614b6d602083018661413f565b614b7a604083018561413f565b614b87606083018461413f565b95945050505050565b7f476174657761793a20696e76616c6964207374617475730000000000000000005f82015250565b5f614bc4601783613db7565b9150614bcf82614b90565b602082019050919050565b5f6020820190508181035f830152614bf181614bb8565b9050919050565b7f496e76616c6964416d6f756e74000000000000000000000000000000000000005f82015250565b5f614c2c600d83613db7565b9150614c3782614bf8565b602082019050919050565b5f6020820190508181035f830152614c5981614c20565b9050919050565b614c698161396d565b82525050565b5f608082019050614c825f83018761413f565b614c8f6020830186613813565b614c9c604083018561413f565b614ca96060830184614c60565b95945050505050565b5f604082019050614cc55f83018561413f565b614cd2602083018461413f565b9392505050565b5f606082019050614cec5f83018661413f565b614cf9602083018561413f565b614d06604083018461413f565b949350505050565b7f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e65725f82015250565b5f614d42602083613db7565b9150614d4d82614d0e565b602082019050919050565b5f6020820190508181035f830152614d6f81614d36565b9050919050565b7f5061757361626c653a20706175736564000000000000000000000000000000005f82015250565b5f614daa601083613db7565b9150614db582614d76565b602082019050919050565b5f6020820190508181035f830152614dd781614d9e565b9050919050565b7f546f6b656e4e6f74537570706f727465640000000000000000000000000000005f82015250565b5f614e12601183613db7565b9150614e1d82614dde565b602082019050919050565b5f6020820190508181035f830152614e3f81614e06565b9050919050565b7f416d6f756e7449735a65726f00000000000000000000000000000000000000005f82015250565b5f614e7a600c83613db7565b9150614e8582614e46565b602082019050919050565b5f6020820190508181035f830152614ea781614e6e565b9050919050565b7f5468726f775a65726f41646472657373000000000000000000000000000000005f82015250565b5f614ee2601083613db7565b9150614eed82614eae565b602082019050919050565b5f6020820190508181035f830152614f0f81614ed6565b9050919050565b7f496e76616c696453656e646572466565526563697069656e74000000000000005f82015250565b5f614f4a601983613db7565b9150614f5582614f16565b602082019050919050565b5f6020820190508181035f830152614f7781614f3e565b9050919050565b7f496e697469616c697a61626c653a20636f6e7472616374206973206e6f7420695f8201527f6e697469616c697a696e67000000000000000000000000000000000000000000602082015250565b5f614fd8602b83613db7565b9150614fe382614f7e565b604082019050919050565b5f6020820190508181035f83015261500581614fcc565b9050919050565b7f5061757361626c653a206e6f74207061757365640000000000000000000000005f82015250565b5f615040601483613db7565b915061504b8261500c565b602082019050919050565b5f6020820190508181035f83015261506d81615034565b905091905056fea2646970667358221220b93bcb97134b7a00def996fb68684bcef988bee715d5ecbb0fcceaa4c5a71df164736f6c634300081e0033",
}

// GatewayABI is the input ABI used to generate the binding from.
// Deprecated: Use GatewayMetaData.ABI instead.
var GatewayABI = GatewayMetaData.ABI

// GatewayBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use GatewayMetaData.Bin instead.
var GatewayBin = GatewayMetaData.Bin

// DeployGateway deploys a new Ethereum contract, binding an instance of Gateway to it.
func DeployGateway(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Gateway, error) {
	parsed, err := GatewayMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(GatewayBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Gateway{GatewayCaller: GatewayCaller{contract: contract}, GatewayTransactor: GatewayTransactor{contract: contract}, GatewayFilterer: GatewayFilterer{contract: contract}}, nil
}

// Gateway is an auto generated Go binding around an Ethereum contract.
type Gateway struct {
	GatewayCaller     // Read-only binding to the contract
	GatewayTransactor // Write-only binding to the contract
	GatewayFilterer   // Log filterer for contract events
}

// GatewayCaller is an auto generated read-only Go binding around an Ethereum contract.
type GatewayCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// GatewayTransactor is an auto generated write-only Go binding around an Ethereum contract.
type GatewayTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// GatewayFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type GatewayFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// GatewaySession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type GatewaySession struct {
	Contract     *Gateway          // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// GatewayCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type GatewayCallerSession struct {
	Contract *GatewayCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts  // Call options to use throughout this session
}

// GatewayTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type GatewayTransactorSession struct {
	Contract     *GatewayTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// GatewayRaw is an auto generated low-level Go binding around an Ethereum contract.
type GatewayRaw struct {
	Contract *Gateway // Generic contract binding to access the raw methods on
}

// GatewayCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type GatewayCallerRaw struct {
	Contract *GatewayCaller // Generic read-only contract binding to access the raw methods on
}

// GatewayTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type GatewayTransactorRaw struct {
	Contract *GatewayTransactor // Generic write-only contract binding to access the raw methods on
}

// NewGateway creates a new instance of Gateway, bound to a specific deployed contract.
func NewGateway(address common.Address, backend bind.ContractBackend) (*Gateway, error) {
	contract, err := bindGateway(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Gateway{GatewayCaller: GatewayCaller{contract: contract}, GatewayTransactor: GatewayTransactor{contract: contract}, GatewayFilterer: GatewayFilterer{contract: contract}}, nil
}

// NewGatewayCaller creates a new read-only instance of Gateway, bound to a specific deployed contract.
func NewGatewayCaller(address common.Address, caller bind.ContractCaller) (*GatewayCaller, error) {
	contract, err := bindGateway(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &GatewayCaller{contract: contract}, nil
}

// NewGatewayTransactor creates a new write-only instance of Gateway, bound to a specific deployed contract.
func NewGatewayTransactor(address common.Address, transactor bind.ContractTransactor) (*GatewayTransactor, error) {
	contract, err := bindGateway(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &GatewayTransactor{contract: contract}, nil
}

// NewGatewayFilterer creates a new log filterer instance of Gateway, bound to a specific deployed contract.
func NewGatewayFilterer(address common.Address, filterer bind.ContractFilterer) (*GatewayFilterer, error) {
	contract, err := bindGateway(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &GatewayFilterer{contract: contract}, nil
}

// bindGateway binds a generic wrapper to an already deployed contract.
func bindGateway(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := GatewayMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Gateway *GatewayRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Gateway.Contract.GatewayCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Gateway *GatewayRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Gateway.Contract.GatewayTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Gateway *GatewayRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Gateway.Contract.GatewayTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Gateway *GatewayCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Gateway.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Gateway *GatewayTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Gateway.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Gateway *GatewayTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Gateway.Contract.contract.Transact(opts, method, params...)
}

// GetAggregator is a free data retrieval call binding the contract method 0x3ad59dbc.
//
// Solidity: function getAggregator() view returns(address)
func (_Gateway *GatewayCaller) GetAggregator(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _Gateway.contract.Call(opts, &out, "getAggregator")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetAggregator is a free data retrieval call binding the contract method 0x3ad59dbc.
//
// Solidity: function getAggregator() view returns(address)
func (_Gateway *GatewaySession) GetAggregator() (common.Address, error) {
	return _Gateway.Contract.GetAggregator(&_Gateway.CallOpts)
}

// GetAggregator is a free data retrieval call binding the contract method 0x3ad59dbc.
//
// Solidity: function getAggregator() view returns(address)
func (_Gateway *GatewayCallerSession) GetAggregator() (common.Address, error) {
	return _Gateway.Contract.GetAggregator(&_Gateway.CallOpts)
}

// GetOrderInfo is a free data retrieval call binding the contract method 0x768c6ec0.
//
// Solidity: function getOrderInfo(bytes32 _orderId) view returns((address,address,address,uint256,uint256,bool,bool,address,uint96,uint256))
func (_Gateway *GatewayCaller) GetOrderInfo(opts *bind.CallOpts, _orderId [32]byte) (IGatewayOrder, error) {
	var out []interface{}
	err := _Gateway.contract.Call(opts, &out, "getOrderInfo", _orderId)

	if err != nil {
		return *new(IGatewayOrder), err
	}

	out0 := *abi.ConvertType(out[0], new(IGatewayOrder)).(*IGatewayOrder)

	return out0, err

}

// GetOrderInfo is a free data retrieval call binding the contract method 0x768c6ec0.
//
// Solidity: function getOrderInfo(bytes32 _orderId) view returns((address,address,address,uint256,uint256,bool,bool,address,uint96,uint256))
func (_Gateway *GatewaySession) GetOrderInfo(_orderId [32]byte) (IGatewayOrder, error) {
	return _Gateway.Contract.GetOrderInfo(&_Gateway.CallOpts, _orderId)
}

// GetOrderInfo is a free data retrieval call binding the contract method 0x768c6ec0.
//
// Solidity: function getOrderInfo(bytes32 _orderId) view returns((address,address,address,uint256,uint256,bool,bool,address,uint96,uint256))
func (_Gateway *GatewayCallerSession) GetOrderInfo(_orderId [32]byte) (IGatewayOrder, error) {
	return _Gateway.Contract.GetOrderInfo(&_Gateway.CallOpts, _orderId)
}

// GetTokenFeeSettings is a free data retrieval call binding the contract method 0x8bfa0549.
//
// Solidity: function getTokenFeeSettings(address token) view returns((uint256,uint256,uint256,uint256))
func (_Gateway *GatewayCaller) GetTokenFeeSettings(opts *bind.CallOpts, token common.Address) (GatewaySettingManagerTokenFeeSettings, error) {
	var out []interface{}
	err := _Gateway.contract.Call(opts, &out, "getTokenFeeSettings", token)

	if err != nil {
		return *new(GatewaySettingManagerTokenFeeSettings), err
	}

	out0 := *abi.ConvertType(out[0], new(GatewaySettingManagerTokenFeeSettings)).(*GatewaySettingManagerTokenFeeSettings)

	return out0, err

}

// GetTokenFeeSettings is a free data retrieval call binding the contract method 0x8bfa0549.
//
// Solidity: function getTokenFeeSettings(address token) view returns((uint256,uint256,uint256,uint256))
func (_Gateway *GatewaySession) GetTokenFeeSettings(token common.Address) (GatewaySettingManagerTokenFeeSettings, error) {
	return _Gateway.Contract.GetTokenFeeSettings(&_Gateway.CallOpts, token)
}

// GetTokenFeeSettings is a free data retrieval call binding the contract method 0x8bfa0549.
//
// Solidity: function getTokenFeeSettings(address token) view returns((uint256,uint256,uint256,uint256))
func (_Gateway *GatewayCallerSession) GetTokenFeeSettings(token common.Address) (GatewaySettingManagerTokenFeeSettings, error) {
	return _Gateway.Contract.GetTokenFeeSettings(&_Gateway.CallOpts, token)
}

// IsTokenSupported is a free data retrieval call binding the contract method 0x75151b63.
//
// Solidity: function isTokenSupported(address _token) view returns(bool)
func (_Gateway *GatewayCaller) IsTokenSupported(opts *bind.CallOpts, _token common.Address) (bool, error) {
	var out []interface{}
	err := _Gateway.contract.Call(opts, &out, "isTokenSupported", _token)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsTokenSupported is a free data retrieval call binding the contract method 0x75151b63.
//
// Solidity: function isTokenSupported(address _token) view returns(bool)
func (_Gateway *GatewaySession) IsTokenSupported(_token common.Address) (bool, error) {
	return _Gateway.Contract.IsTokenSupported(&_Gateway.CallOpts, _token)
}

// IsTokenSupported is a free data retrieval call binding the contract method 0x75151b63.
//
// Solidity: function isTokenSupported(address _token) view returns(bool)
func (_Gateway *GatewayCallerSession) IsTokenSupported(_token common.Address) (bool, error) {
	return _Gateway.Contract.IsTokenSupported(&_Gateway.CallOpts, _token)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_Gateway *GatewayCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _Gateway.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_Gateway *GatewaySession) Owner() (common.Address, error) {
	return _Gateway.Contract.Owner(&_Gateway.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_Gateway *GatewayCallerSession) Owner() (common.Address, error) {
	return _Gateway.Contract.Owner(&_Gateway.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_Gateway *GatewayCaller) Paused(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	err := _Gateway.contract.Call(opts, &out, "paused")

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_Gateway *GatewaySession) Paused() (bool, error) {
	return _Gateway.Contract.Paused(&_Gateway.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_Gateway *GatewayCallerSession) Paused() (bool, error) {
	return _Gateway.Contract.Paused(&_Gateway.CallOpts)
}

// PendingOwner is a free data retrieval call binding the contract method 0xe30c3978.
//
// Solidity: function pendingOwner() view returns(address)
func (_Gateway *GatewayCaller) PendingOwner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _Gateway.contract.Call(opts, &out, "pendingOwner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// PendingOwner is a free data retrieval call binding the contract method 0xe30c3978.
//
// Solidity: function pendingOwner() view returns(address)
func (_Gateway *GatewaySession) PendingOwner() (common.Address, error) {
	return _Gateway.Contract.PendingOwner(&_Gateway.CallOpts)
}

// PendingOwner is a free data retrieval call binding the contract method 0xe30c3978.
//
// Solidity: function pendingOwner() view returns(address)
func (_Gateway *GatewayCallerSession) PendingOwner() (common.Address, error) {
	return _Gateway.Contract.PendingOwner(&_Gateway.CallOpts)
}

// AcceptOwnership is a paid mutator transaction binding the contract method 0x79ba5097.
//
// Solidity: function acceptOwnership() returns()
func (_Gateway *GatewayTransactor) AcceptOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Gateway.contract.Transact(opts, "acceptOwnership")
}

// AcceptOwnership is a paid mutator transaction binding the contract method 0x79ba5097.
//
// Solidity: function acceptOwnership() returns()
func (_Gateway *GatewaySession) AcceptOwnership() (*types.Transaction, error) {
	return _Gateway.Contract.AcceptOwnership(&_Gateway.TransactOpts)
}

// AcceptOwnership is a paid mutator transaction binding the contract method 0x79ba5097.
//
// Solidity: function acceptOwnership() returns()
func (_Gateway *GatewayTransactorSession) AcceptOwnership() (*types.Transaction, error) {
	return _Gateway.Contract.AcceptOwnership(&_Gateway.TransactOpts)
}

// CreateOrder is a paid mutator transaction binding the contract method 0x809804f7.
//
// Solidity: function createOrder(address _token, uint256 _amount, uint96 _rate, address _senderFeeRecipient, uint256 _senderFee, address _refundAddress, string messageHash) returns(bytes32 orderId)
func (_Gateway *GatewayTransactor) CreateOrder(opts *bind.TransactOpts, _token common.Address, _amount *big.Int, _rate *big.Int, _senderFeeRecipient common.Address, _senderFee *big.Int, _refundAddress common.Address, messageHash string) (*types.Transaction, error) {
	return _Gateway.contract.Transact(opts, "createOrder", _token, _amount, _rate, _senderFeeRecipient, _senderFee, _refundAddress, messageHash)
}

// CreateOrder is a paid mutator transaction binding the contract method 0x809804f7.
//
// Solidity: function createOrder(address _token, uint256 _amount, uint96 _rate, address _senderFeeRecipient, uint256 _senderFee, address _refundAddress, string messageHash) returns(bytes32 orderId)
func (_Gateway *GatewaySession) CreateOrder(_token common.Address, _amount *big.Int, _rate *big.Int, _senderFeeRecipient common.Address, _senderFee *big.Int, _refundAddress common.Address, messageHash string) (*types.Transaction, error) {
	return _Gateway.Contract.CreateOrder(&_Gateway.TransactOpts, _token, _amount, _rate, _senderFeeRecipient, _senderFee, _refundAddress, messageHash)
}

// CreateOrder is a paid mutator transaction binding the contract method 0x809804f7.
//
// Solidity: function createOrder(address _token, uint256 _amount, uint96 _rate, address _senderFeeRecipient, uint256 _senderFee, address _refundAddress, string messageHash) returns(bytes32 orderId)
func (_Gateway *GatewayTransactorSession) CreateOrder(_token common.Address, _amount *big.Int, _rate *big.Int, _senderFeeRecipient common.Address, _senderFee *big.Int, _refundAddress common.Address, messageHash string) (*types.Transaction, error) {
	return _Gateway.Contract.CreateOrder(&_Gateway.TransactOpts, _token, _amount, _rate, _senderFeeRecipient, _senderFee, _refundAddress, messageHash)
}

// Initialize is a paid mutator transaction binding the contract method 0x8129fc1c.
//
// Solidity: function initialize() returns()
func (_Gateway *GatewayTransactor) Initialize(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Gateway.contract.Transact(opts, "initialize")
}

// Initialize is a paid mutator transaction binding the contract method 0x8129fc1c.
//
// Solidity: function initialize() returns()
func (_Gateway *GatewaySession) Initialize() (*types.Transaction, error) {
	return _Gateway.Contract.Initialize(&_Gateway.TransactOpts)
}

// Initialize is a paid mutator transaction binding the contract method 0x8129fc1c.
//
// Solidity: function initialize() returns()
func (_Gateway *GatewayTransactorSession) Initialize() (*types.Transaction, error) {
	return _Gateway.Contract.Initialize(&_Gateway.TransactOpts)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_Gateway *GatewayTransactor) Pause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Gateway.contract.Transact(opts, "pause")
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_Gateway *GatewaySession) Pause() (*types.Transaction, error) {
	return _Gateway.Contract.Pause(&_Gateway.TransactOpts)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_Gateway *GatewayTransactorSession) Pause() (*types.Transaction, error) {
	return _Gateway.Contract.Pause(&_Gateway.TransactOpts)
}

// Refund is a paid mutator transaction binding the contract method 0x71eedb88.
//
// Solidity: function refund(uint256 _fee, bytes32 _orderId) returns(bool)
func (_Gateway *GatewayTransactor) Refund(opts *bind.TransactOpts, _fee *big.Int, _orderId [32]byte) (*types.Transaction, error) {
	return _Gateway.contract.Transact(opts, "refund", _fee, _orderId)
}

// Refund is a paid mutator transaction binding the contract method 0x71eedb88.
//
// Solidity: function refund(uint256 _fee, bytes32 _orderId) returns(bool)
func (_Gateway *GatewaySession) Refund(_fee *big.Int, _orderId [32]byte) (*types.Transaction, error) {
	return _Gateway.Contract.Refund(&_Gateway.TransactOpts, _fee, _orderId)
}

// Refund is a paid mutator transaction binding the contract method 0x71eedb88.
//
// Solidity: function refund(uint256 _fee, bytes32 _orderId) returns(bool)
func (_Gateway *GatewayTransactorSession) Refund(_fee *big.Int, _orderId [32]byte) (*types.Transaction, error) {
	return _Gateway.Contract.Refund(&_Gateway.TransactOpts, _fee, _orderId)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_Gateway *GatewayTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Gateway.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_Gateway *GatewaySession) RenounceOwnership() (*types.Transaction, error) {
	return _Gateway.Contract.RenounceOwnership(&_Gateway.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_Gateway *GatewayTransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _Gateway.Contract.RenounceOwnership(&_Gateway.TransactOpts)
}

// SetTokenFeeSettings is a paid mutator transaction binding the contract method 0x898861b0.
//
// Solidity: function setTokenFeeSettings(address token, uint256 senderToProvider, uint256 providerToAggregator, uint256 senderToAggregator, uint256 providerToAggregatorFx) returns()
func (_Gateway *GatewayTransactor) SetTokenFeeSettings(opts *bind.TransactOpts, token common.Address, senderToProvider *big.Int, providerToAggregator *big.Int, senderToAggregator *big.Int, providerToAggregatorFx *big.Int) (*types.Transaction, error) {
	return _Gateway.contract.Transact(opts, "setTokenFeeSettings", token, senderToProvider, providerToAggregator, senderToAggregator, providerToAggregatorFx)
}

// SetTokenFeeSettings is a paid mutator transaction binding the contract method 0x898861b0.
//
// Solidity: function setTokenFeeSettings(address token, uint256 senderToProvider, uint256 providerToAggregator, uint256 senderToAggregator, uint256 providerToAggregatorFx) returns()
func (_Gateway *GatewaySession) SetTokenFeeSettings(token common.Address, senderToProvider *big.Int, providerToAggregator *big.Int, senderToAggregator *big.Int, providerToAggregatorFx *big.Int) (*types.Transaction, error) {
	return _Gateway.Contract.SetTokenFeeSettings(&_Gateway.TransactOpts, token, senderToProvider, providerToAggregator, senderToAggregator, providerToAggregatorFx)
}

// SetTokenFeeSettings is a paid mutator transaction binding the contract method 0x898861b0.
//
// Solidity: function setTokenFeeSettings(address token, uint256 senderToProvider, uint256 providerToAggregator, uint256 senderToAggregator, uint256 providerToAggregatorFx) returns()
func (_Gateway *GatewayTransactorSession) SetTokenFeeSettings(token common.Address, senderToProvider *big.Int, providerToAggregator *big.Int, senderToAggregator *big.Int, providerToAggregatorFx *big.Int) (*types.Transaction, error) {
	return _Gateway.Contract.SetTokenFeeSettings(&_Gateway.TransactOpts, token, senderToProvider, providerToAggregator, senderToAggregator, providerToAggregatorFx)
}

// SettingManagerBool is a paid mutator transaction binding the contract method 0xcd992400.
//
// Solidity: function settingManagerBool(bytes32 what, address value, uint256 status) returns()
func (_Gateway *GatewayTransactor) SettingManagerBool(opts *bind.TransactOpts, what [32]byte, value common.Address, status *big.Int) (*types.Transaction, error) {
	return _Gateway.contract.Transact(opts, "settingManagerBool", what, value, status)
}

// SettingManagerBool is a paid mutator transaction binding the contract method 0xcd992400.
//
// Solidity: function settingManagerBool(bytes32 what, address value, uint256 status) returns()
func (_Gateway *GatewaySession) SettingManagerBool(what [32]byte, value common.Address, status *big.Int) (*types.Transaction, error) {
	return _Gateway.Contract.SettingManagerBool(&_Gateway.TransactOpts, what, value, status)
}

// SettingManagerBool is a paid mutator transaction binding the contract method 0xcd992400.
//
// Solidity: function settingManagerBool(bytes32 what, address value, uint256 status) returns()
func (_Gateway *GatewayTransactorSession) SettingManagerBool(what [32]byte, value common.Address, status *big.Int) (*types.Transaction, error) {
	return _Gateway.Contract.SettingManagerBool(&_Gateway.TransactOpts, what, value, status)
}

// SettleIn is a paid mutator transaction binding the contract method 0xd839de63.
//
// Solidity: function settleIn(bytes32 _orderId, address _token, uint256 _amount, address _senderFeeRecipient, uint96 _senderFee, address _recipient, uint96 _rate) returns(bool)
func (_Gateway *GatewayTransactor) SettleIn(opts *bind.TransactOpts, _orderId [32]byte, _token common.Address, _amount *big.Int, _senderFeeRecipient common.Address, _senderFee *big.Int, _recipient common.Address, _rate *big.Int) (*types.Transaction, error) {
	return _Gateway.contract.Transact(opts, "settleIn", _orderId, _token, _amount, _senderFeeRecipient, _senderFee, _recipient, _rate)
}

// SettleIn is a paid mutator transaction binding the contract method 0xd839de63.
//
// Solidity: function settleIn(bytes32 _orderId, address _token, uint256 _amount, address _senderFeeRecipient, uint96 _senderFee, address _recipient, uint96 _rate) returns(bool)
func (_Gateway *GatewaySession) SettleIn(_orderId [32]byte, _token common.Address, _amount *big.Int, _senderFeeRecipient common.Address, _senderFee *big.Int, _recipient common.Address, _rate *big.Int) (*types.Transaction, error) {
	return _Gateway.Contract.SettleIn(&_Gateway.TransactOpts, _orderId, _token, _amount, _senderFeeRecipient, _senderFee, _recipient, _rate)
}

// SettleIn is a paid mutator transaction binding the contract method 0xd839de63.
//
// Solidity: function settleIn(bytes32 _orderId, address _token, uint256 _amount, address _senderFeeRecipient, uint96 _senderFee, address _recipient, uint96 _rate) returns(bool)
func (_Gateway *GatewayTransactorSession) SettleIn(_orderId [32]byte, _token common.Address, _amount *big.Int, _senderFeeRecipient common.Address, _senderFee *big.Int, _recipient common.Address, _rate *big.Int) (*types.Transaction, error) {
	return _Gateway.Contract.SettleIn(&_Gateway.TransactOpts, _orderId, _token, _amount, _senderFeeRecipient, _senderFee, _recipient, _rate)
}

// SettleOut is a paid mutator transaction binding the contract method 0x32553efa.
//
// Solidity: function settleOut(bytes32 _splitOrderId, bytes32 _orderId, address _liquidityProvider, uint64 _settlePercent, uint64 _rebatePercent) returns(bool)
func (_Gateway *GatewayTransactor) SettleOut(opts *bind.TransactOpts, _splitOrderId [32]byte, _orderId [32]byte, _liquidityProvider common.Address, _settlePercent uint64, _rebatePercent uint64) (*types.Transaction, error) {
	return _Gateway.contract.Transact(opts, "settleOut", _splitOrderId, _orderId, _liquidityProvider, _settlePercent, _rebatePercent)
}

// SettleOut is a paid mutator transaction binding the contract method 0x32553efa.
//
// Solidity: function settleOut(bytes32 _splitOrderId, bytes32 _orderId, address _liquidityProvider, uint64 _settlePercent, uint64 _rebatePercent) returns(bool)
func (_Gateway *GatewaySession) SettleOut(_splitOrderId [32]byte, _orderId [32]byte, _liquidityProvider common.Address, _settlePercent uint64, _rebatePercent uint64) (*types.Transaction, error) {
	return _Gateway.Contract.SettleOut(&_Gateway.TransactOpts, _splitOrderId, _orderId, _liquidityProvider, _settlePercent, _rebatePercent)
}

// SettleOut is a paid mutator transaction binding the contract method 0x32553efa.
//
// Solidity: function settleOut(bytes32 _splitOrderId, bytes32 _orderId, address _liquidityProvider, uint64 _settlePercent, uint64 _rebatePercent) returns(bool)
func (_Gateway *GatewayTransactorSession) SettleOut(_splitOrderId [32]byte, _orderId [32]byte, _liquidityProvider common.Address, _settlePercent uint64, _rebatePercent uint64) (*types.Transaction, error) {
	return _Gateway.Contract.SettleOut(&_Gateway.TransactOpts, _splitOrderId, _orderId, _liquidityProvider, _settlePercent, _rebatePercent)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Gateway *GatewayTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _Gateway.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Gateway *GatewaySession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _Gateway.Contract.TransferOwnership(&_Gateway.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Gateway *GatewayTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _Gateway.Contract.TransferOwnership(&_Gateway.TransactOpts, newOwner)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_Gateway *GatewayTransactor) Unpause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Gateway.contract.Transact(opts, "unpause")
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_Gateway *GatewaySession) Unpause() (*types.Transaction, error) {
	return _Gateway.Contract.Unpause(&_Gateway.TransactOpts)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_Gateway *GatewayTransactorSession) Unpause() (*types.Transaction, error) {
	return _Gateway.Contract.Unpause(&_Gateway.TransactOpts)
}

// UpdateProtocolAddress is a paid mutator transaction binding the contract method 0x40ebc677.
//
// Solidity: function updateProtocolAddress(bytes32 what, address value) returns()
func (_Gateway *GatewayTransactor) UpdateProtocolAddress(opts *bind.TransactOpts, what [32]byte, value common.Address) (*types.Transaction, error) {
	return _Gateway.contract.Transact(opts, "updateProtocolAddress", what, value)
}

// UpdateProtocolAddress is a paid mutator transaction binding the contract method 0x40ebc677.
//
// Solidity: function updateProtocolAddress(bytes32 what, address value) returns()
func (_Gateway *GatewaySession) UpdateProtocolAddress(what [32]byte, value common.Address) (*types.Transaction, error) {
	return _Gateway.Contract.UpdateProtocolAddress(&_Gateway.TransactOpts, what, value)
}

// UpdateProtocolAddress is a paid mutator transaction binding the contract method 0x40ebc677.
//
// Solidity: function updateProtocolAddress(bytes32 what, address value) returns()
func (_Gateway *GatewayTransactorSession) UpdateProtocolAddress(what [32]byte, value common.Address) (*types.Transaction, error) {
	return _Gateway.Contract.UpdateProtocolAddress(&_Gateway.TransactOpts, what, value)
}

// GatewayFxTransferFeeSplitIterator is returned from FilterFxTransferFeeSplit and is used to iterate over the raw logs and unpacked data for FxTransferFeeSplit events raised by the Gateway contract.
type GatewayFxTransferFeeSplitIterator struct {
	Event *GatewayFxTransferFeeSplit // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *GatewayFxTransferFeeSplitIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(GatewayFxTransferFeeSplit)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(GatewayFxTransferFeeSplit)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *GatewayFxTransferFeeSplitIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *GatewayFxTransferFeeSplitIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// GatewayFxTransferFeeSplit represents a FxTransferFeeSplit event raised by the Gateway contract.
type GatewayFxTransferFeeSplit struct {
	OrderId          [32]byte
	SenderAmount     *big.Int
	AggregatorAmount *big.Int
	Raw              types.Log // Blockchain specific contextual infos
}

// FilterFxTransferFeeSplit is a free log retrieval operation binding the contract event 0x88592047496a7850992dc5e8cd92a9b633cef0d191a4f5e87fd745c7d382630a.
//
// Solidity: event FxTransferFeeSplit(bytes32 indexed orderId, uint256 senderAmount, uint256 aggregatorAmount)
func (_Gateway *GatewayFilterer) FilterFxTransferFeeSplit(opts *bind.FilterOpts, orderId [][32]byte) (*GatewayFxTransferFeeSplitIterator, error) {

	var orderIdRule []interface{}
	for _, orderIdItem := range orderId {
		orderIdRule = append(orderIdRule, orderIdItem)
	}

	logs, sub, err := _Gateway.contract.FilterLogs(opts, "FxTransferFeeSplit", orderIdRule)
	if err != nil {
		return nil, err
	}
	return &GatewayFxTransferFeeSplitIterator{contract: _Gateway.contract, event: "FxTransferFeeSplit", logs: logs, sub: sub}, nil
}

// WatchFxTransferFeeSplit is a free log subscription operation binding the contract event 0x88592047496a7850992dc5e8cd92a9b633cef0d191a4f5e87fd745c7d382630a.
//
// Solidity: event FxTransferFeeSplit(bytes32 indexed orderId, uint256 senderAmount, uint256 aggregatorAmount)
func (_Gateway *GatewayFilterer) WatchFxTransferFeeSplit(opts *bind.WatchOpts, sink chan<- *GatewayFxTransferFeeSplit, orderId [][32]byte) (event.Subscription, error) {

	var orderIdRule []interface{}
	for _, orderIdItem := range orderId {
		orderIdRule = append(orderIdRule, orderIdItem)
	}

	logs, sub, err := _Gateway.contract.WatchLogs(opts, "FxTransferFeeSplit", orderIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(GatewayFxTransferFeeSplit)
				if err := _Gateway.contract.UnpackLog(event, "FxTransferFeeSplit", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseFxTransferFeeSplit is a log parse operation binding the contract event 0x88592047496a7850992dc5e8cd92a9b633cef0d191a4f5e87fd745c7d382630a.
//
// Solidity: event FxTransferFeeSplit(bytes32 indexed orderId, uint256 senderAmount, uint256 aggregatorAmount)
func (_Gateway *GatewayFilterer) ParseFxTransferFeeSplit(log types.Log) (*GatewayFxTransferFeeSplit, error) {
	event := new(GatewayFxTransferFeeSplit)
	if err := _Gateway.contract.UnpackLog(event, "FxTransferFeeSplit", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// GatewayInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the Gateway contract.
type GatewayInitializedIterator struct {
	Event *GatewayInitialized // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *GatewayInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(GatewayInitialized)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(GatewayInitialized)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *GatewayInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *GatewayInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// GatewayInitialized represents a Initialized event raised by the Gateway contract.
type GatewayInitialized struct {
	Version uint8
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_Gateway *GatewayFilterer) FilterInitialized(opts *bind.FilterOpts) (*GatewayInitializedIterator, error) {

	logs, sub, err := _Gateway.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &GatewayInitializedIterator{contract: _Gateway.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_Gateway *GatewayFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *GatewayInitialized) (event.Subscription, error) {

	logs, sub, err := _Gateway.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(GatewayInitialized)
				if err := _Gateway.contract.UnpackLog(event, "Initialized", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseInitialized is a log parse operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_Gateway *GatewayFilterer) ParseInitialized(log types.Log) (*GatewayInitialized, error) {
	event := new(GatewayInitialized)
	if err := _Gateway.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// GatewayLocalTransferFeeSplitIterator is returned from FilterLocalTransferFeeSplit and is used to iterate over the raw logs and unpacked data for LocalTransferFeeSplit events raised by the Gateway contract.
type GatewayLocalTransferFeeSplitIterator struct {
	Event *GatewayLocalTransferFeeSplit // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *GatewayLocalTransferFeeSplitIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(GatewayLocalTransferFeeSplit)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(GatewayLocalTransferFeeSplit)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *GatewayLocalTransferFeeSplitIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *GatewayLocalTransferFeeSplitIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// GatewayLocalTransferFeeSplit represents a LocalTransferFeeSplit event raised by the Gateway contract.
type GatewayLocalTransferFeeSplit struct {
	OrderId          [32]byte
	SenderAmount     *big.Int
	ProviderAmount   *big.Int
	AggregatorAmount *big.Int
	Raw              types.Log // Blockchain specific contextual infos
}

// FilterLocalTransferFeeSplit is a free log retrieval operation binding the contract event 0x831c7cc0006d91462607c476603366c48469d125de6228c0791a7090efd7f7a4.
//
// Solidity: event LocalTransferFeeSplit(bytes32 indexed orderId, uint256 senderAmount, uint256 providerAmount, uint256 aggregatorAmount)
func (_Gateway *GatewayFilterer) FilterLocalTransferFeeSplit(opts *bind.FilterOpts, orderId [][32]byte) (*GatewayLocalTransferFeeSplitIterator, error) {

	var orderIdRule []interface{}
	for _, orderIdItem := range orderId {
		orderIdRule = append(orderIdRule, orderIdItem)
	}

	logs, sub, err := _Gateway.contract.FilterLogs(opts, "LocalTransferFeeSplit", orderIdRule)
	if err != nil {
		return nil, err
	}
	return &GatewayLocalTransferFeeSplitIterator{contract: _Gateway.contract, event: "LocalTransferFeeSplit", logs: logs, sub: sub}, nil
}

// WatchLocalTransferFeeSplit is a free log subscription operation binding the contract event 0x831c7cc0006d91462607c476603366c48469d125de6228c0791a7090efd7f7a4.
//
// Solidity: event LocalTransferFeeSplit(bytes32 indexed orderId, uint256 senderAmount, uint256 providerAmount, uint256 aggregatorAmount)
func (_Gateway *GatewayFilterer) WatchLocalTransferFeeSplit(opts *bind.WatchOpts, sink chan<- *GatewayLocalTransferFeeSplit, orderId [][32]byte) (event.Subscription, error) {

	var orderIdRule []interface{}
	for _, orderIdItem := range orderId {
		orderIdRule = append(orderIdRule, orderIdItem)
	}

	logs, sub, err := _Gateway.contract.WatchLogs(opts, "LocalTransferFeeSplit", orderIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(GatewayLocalTransferFeeSplit)
				if err := _Gateway.contract.UnpackLog(event, "LocalTransferFeeSplit", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseLocalTransferFeeSplit is a log parse operation binding the contract event 0x831c7cc0006d91462607c476603366c48469d125de6228c0791a7090efd7f7a4.
//
// Solidity: event LocalTransferFeeSplit(bytes32 indexed orderId, uint256 senderAmount, uint256 providerAmount, uint256 aggregatorAmount)
func (_Gateway *GatewayFilterer) ParseLocalTransferFeeSplit(log types.Log) (*GatewayLocalTransferFeeSplit, error) {
	event := new(GatewayLocalTransferFeeSplit)
	if err := _Gateway.contract.UnpackLog(event, "LocalTransferFeeSplit", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// GatewayOrderCreatedIterator is returned from FilterOrderCreated and is used to iterate over the raw logs and unpacked data for OrderCreated events raised by the Gateway contract.
type GatewayOrderCreatedIterator struct {
	Event *GatewayOrderCreated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *GatewayOrderCreatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(GatewayOrderCreated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(GatewayOrderCreated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *GatewayOrderCreatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *GatewayOrderCreatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// GatewayOrderCreated represents a OrderCreated event raised by the Gateway contract.
type GatewayOrderCreated struct {
	Sender      common.Address
	Token       common.Address
	Amount      *big.Int
	ProtocolFee *big.Int
	OrderId     [32]byte
	Rate        *big.Int
	MessageHash string
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterOrderCreated is a free log retrieval operation binding the contract event 0x40ccd1ceb111a3c186ef9911e1b876dc1f789ed331b86097b3b8851055b6a137.
//
// Solidity: event OrderCreated(address indexed sender, address indexed token, uint256 indexed amount, uint256 protocolFee, bytes32 orderId, uint256 rate, string messageHash)
func (_Gateway *GatewayFilterer) FilterOrderCreated(opts *bind.FilterOpts, sender []common.Address, token []common.Address, amount []*big.Int) (*GatewayOrderCreatedIterator, error) {

	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}
	var tokenRule []interface{}
	for _, tokenItem := range token {
		tokenRule = append(tokenRule, tokenItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}

	logs, sub, err := _Gateway.contract.FilterLogs(opts, "OrderCreated", senderRule, tokenRule, amountRule)
	if err != nil {
		return nil, err
	}
	return &GatewayOrderCreatedIterator{contract: _Gateway.contract, event: "OrderCreated", logs: logs, sub: sub}, nil
}

// WatchOrderCreated is a free log subscription operation binding the contract event 0x40ccd1ceb111a3c186ef9911e1b876dc1f789ed331b86097b3b8851055b6a137.
//
// Solidity: event OrderCreated(address indexed sender, address indexed token, uint256 indexed amount, uint256 protocolFee, bytes32 orderId, uint256 rate, string messageHash)
func (_Gateway *GatewayFilterer) WatchOrderCreated(opts *bind.WatchOpts, sink chan<- *GatewayOrderCreated, sender []common.Address, token []common.Address, amount []*big.Int) (event.Subscription, error) {

	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}
	var tokenRule []interface{}
	for _, tokenItem := range token {
		tokenRule = append(tokenRule, tokenItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}

	logs, sub, err := _Gateway.contract.WatchLogs(opts, "OrderCreated", senderRule, tokenRule, amountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(GatewayOrderCreated)
				if err := _Gateway.contract.UnpackLog(event, "OrderCreated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOrderCreated is a log parse operation binding the contract event 0x40ccd1ceb111a3c186ef9911e1b876dc1f789ed331b86097b3b8851055b6a137.
//
// Solidity: event OrderCreated(address indexed sender, address indexed token, uint256 indexed amount, uint256 protocolFee, bytes32 orderId, uint256 rate, string messageHash)
func (_Gateway *GatewayFilterer) ParseOrderCreated(log types.Log) (*GatewayOrderCreated, error) {
	event := new(GatewayOrderCreated)
	if err := _Gateway.contract.UnpackLog(event, "OrderCreated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// GatewayOrderRefundedIterator is returned from FilterOrderRefunded and is used to iterate over the raw logs and unpacked data for OrderRefunded events raised by the Gateway contract.
type GatewayOrderRefundedIterator struct {
	Event *GatewayOrderRefunded // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *GatewayOrderRefundedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(GatewayOrderRefunded)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(GatewayOrderRefunded)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *GatewayOrderRefundedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *GatewayOrderRefundedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// GatewayOrderRefunded represents a OrderRefunded event raised by the Gateway contract.
type GatewayOrderRefunded struct {
	Fee     *big.Int
	OrderId [32]byte
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterOrderRefunded is a free log retrieval operation binding the contract event 0x0736fe428e1747ca8d387c2e6fa1a31a0cde62d3a167c40a46ade59a3cdc828e.
//
// Solidity: event OrderRefunded(uint256 fee, bytes32 indexed orderId)
func (_Gateway *GatewayFilterer) FilterOrderRefunded(opts *bind.FilterOpts, orderId [][32]byte) (*GatewayOrderRefundedIterator, error) {

	var orderIdRule []interface{}
	for _, orderIdItem := range orderId {
		orderIdRule = append(orderIdRule, orderIdItem)
	}

	logs, sub, err := _Gateway.contract.FilterLogs(opts, "OrderRefunded", orderIdRule)
	if err != nil {
		return nil, err
	}
	return &GatewayOrderRefundedIterator{contract: _Gateway.contract, event: "OrderRefunded", logs: logs, sub: sub}, nil
}

// WatchOrderRefunded is a free log subscription operation binding the contract event 0x0736fe428e1747ca8d387c2e6fa1a31a0cde62d3a167c40a46ade59a3cdc828e.
//
// Solidity: event OrderRefunded(uint256 fee, bytes32 indexed orderId)
func (_Gateway *GatewayFilterer) WatchOrderRefunded(opts *bind.WatchOpts, sink chan<- *GatewayOrderRefunded, orderId [][32]byte) (event.Subscription, error) {

	var orderIdRule []interface{}
	for _, orderIdItem := range orderId {
		orderIdRule = append(orderIdRule, orderIdItem)
	}

	logs, sub, err := _Gateway.contract.WatchLogs(opts, "OrderRefunded", orderIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(GatewayOrderRefunded)
				if err := _Gateway.contract.UnpackLog(event, "OrderRefunded", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOrderRefunded is a log parse operation binding the contract event 0x0736fe428e1747ca8d387c2e6fa1a31a0cde62d3a167c40a46ade59a3cdc828e.
//
// Solidity: event OrderRefunded(uint256 fee, bytes32 indexed orderId)
func (_Gateway *GatewayFilterer) ParseOrderRefunded(log types.Log) (*GatewayOrderRefunded, error) {
	event := new(GatewayOrderRefunded)
	if err := _Gateway.contract.UnpackLog(event, "OrderRefunded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// GatewayOwnershipTransferStartedIterator is returned from FilterOwnershipTransferStarted and is used to iterate over the raw logs and unpacked data for OwnershipTransferStarted events raised by the Gateway contract.
type GatewayOwnershipTransferStartedIterator struct {
	Event *GatewayOwnershipTransferStarted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *GatewayOwnershipTransferStartedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(GatewayOwnershipTransferStarted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(GatewayOwnershipTransferStarted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *GatewayOwnershipTransferStartedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *GatewayOwnershipTransferStartedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// GatewayOwnershipTransferStarted represents a OwnershipTransferStarted event raised by the Gateway contract.
type GatewayOwnershipTransferStarted struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferStarted is a free log retrieval operation binding the contract event 0x38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e22700.
//
// Solidity: event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner)
func (_Gateway *GatewayFilterer) FilterOwnershipTransferStarted(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*GatewayOwnershipTransferStartedIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _Gateway.contract.FilterLogs(opts, "OwnershipTransferStarted", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &GatewayOwnershipTransferStartedIterator{contract: _Gateway.contract, event: "OwnershipTransferStarted", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferStarted is a free log subscription operation binding the contract event 0x38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e22700.
//
// Solidity: event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner)
func (_Gateway *GatewayFilterer) WatchOwnershipTransferStarted(opts *bind.WatchOpts, sink chan<- *GatewayOwnershipTransferStarted, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _Gateway.contract.WatchLogs(opts, "OwnershipTransferStarted", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(GatewayOwnershipTransferStarted)
				if err := _Gateway.contract.UnpackLog(event, "OwnershipTransferStarted", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipTransferStarted is a log parse operation binding the contract event 0x38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e22700.
//
// Solidity: event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner)
func (_Gateway *GatewayFilterer) ParseOwnershipTransferStarted(log types.Log) (*GatewayOwnershipTransferStarted, error) {
	event := new(GatewayOwnershipTransferStarted)
	if err := _Gateway.contract.UnpackLog(event, "OwnershipTransferStarted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// GatewayOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the Gateway contract.
type GatewayOwnershipTransferredIterator struct {
	Event *GatewayOwnershipTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *GatewayOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(GatewayOwnershipTransferred)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(GatewayOwnershipTransferred)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *GatewayOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *GatewayOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// GatewayOwnershipTransferred represents a OwnershipTransferred event raised by the Gateway contract.
type GatewayOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_Gateway *GatewayFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*GatewayOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _Gateway.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &GatewayOwnershipTransferredIterator{contract: _Gateway.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_Gateway *GatewayFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *GatewayOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _Gateway.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(GatewayOwnershipTransferred)
				if err := _Gateway.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_Gateway *GatewayFilterer) ParseOwnershipTransferred(log types.Log) (*GatewayOwnershipTransferred, error) {
	event := new(GatewayOwnershipTransferred)
	if err := _Gateway.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// GatewayPausedIterator is returned from FilterPaused and is used to iterate over the raw logs and unpacked data for Paused events raised by the Gateway contract.
type GatewayPausedIterator struct {
	Event *GatewayPaused // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *GatewayPausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(GatewayPaused)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(GatewayPaused)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *GatewayPausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *GatewayPausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// GatewayPaused represents a Paused event raised by the Gateway contract.
type GatewayPaused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterPaused is a free log retrieval operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_Gateway *GatewayFilterer) FilterPaused(opts *bind.FilterOpts) (*GatewayPausedIterator, error) {

	logs, sub, err := _Gateway.contract.FilterLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return &GatewayPausedIterator{contract: _Gateway.contract, event: "Paused", logs: logs, sub: sub}, nil
}

// WatchPaused is a free log subscription operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_Gateway *GatewayFilterer) WatchPaused(opts *bind.WatchOpts, sink chan<- *GatewayPaused) (event.Subscription, error) {

	logs, sub, err := _Gateway.contract.WatchLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(GatewayPaused)
				if err := _Gateway.contract.UnpackLog(event, "Paused", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParsePaused is a log parse operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_Gateway *GatewayFilterer) ParsePaused(log types.Log) (*GatewayPaused, error) {
	event := new(GatewayPaused)
	if err := _Gateway.contract.UnpackLog(event, "Paused", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// GatewayProtocolAddressUpdatedIterator is returned from FilterProtocolAddressUpdated and is used to iterate over the raw logs and unpacked data for ProtocolAddressUpdated events raised by the Gateway contract.
type GatewayProtocolAddressUpdatedIterator struct {
	Event *GatewayProtocolAddressUpdated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *GatewayProtocolAddressUpdatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(GatewayProtocolAddressUpdated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(GatewayProtocolAddressUpdated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *GatewayProtocolAddressUpdatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *GatewayProtocolAddressUpdatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// GatewayProtocolAddressUpdated represents a ProtocolAddressUpdated event raised by the Gateway contract.
type GatewayProtocolAddressUpdated struct {
	What            [32]byte
	TreasuryAddress common.Address
	Raw             types.Log // Blockchain specific contextual infos
}

// FilterProtocolAddressUpdated is a free log retrieval operation binding the contract event 0xbbc5b96e57cfecb3dbeeadf92e87f15e58e64fcd75cbe256dcc5d9ef2e51e8a4.
//
// Solidity: event ProtocolAddressUpdated(bytes32 indexed what, address indexed treasuryAddress)
func (_Gateway *GatewayFilterer) FilterProtocolAddressUpdated(opts *bind.FilterOpts, what [][32]byte, treasuryAddress []common.Address) (*GatewayProtocolAddressUpdatedIterator, error) {

	var whatRule []interface{}
	for _, whatItem := range what {
		whatRule = append(whatRule, whatItem)
	}
	var treasuryAddressRule []interface{}
	for _, treasuryAddressItem := range treasuryAddress {
		treasuryAddressRule = append(treasuryAddressRule, treasuryAddressItem)
	}

	logs, sub, err := _Gateway.contract.FilterLogs(opts, "ProtocolAddressUpdated", whatRule, treasuryAddressRule)
	if err != nil {
		return nil, err
	}
	return &GatewayProtocolAddressUpdatedIterator{contract: _Gateway.contract, event: "ProtocolAddressUpdated", logs: logs, sub: sub}, nil
}

// WatchProtocolAddressUpdated is a free log subscription operation binding the contract event 0xbbc5b96e57cfecb3dbeeadf92e87f15e58e64fcd75cbe256dcc5d9ef2e51e8a4.
//
// Solidity: event ProtocolAddressUpdated(bytes32 indexed what, address indexed treasuryAddress)
func (_Gateway *GatewayFilterer) WatchProtocolAddressUpdated(opts *bind.WatchOpts, sink chan<- *GatewayProtocolAddressUpdated, what [][32]byte, treasuryAddress []common.Address) (event.Subscription, error) {

	var whatRule []interface{}
	for _, whatItem := range what {
		whatRule = append(whatRule, whatItem)
	}
	var treasuryAddressRule []interface{}
	for _, treasuryAddressItem := range treasuryAddress {
		treasuryAddressRule = append(treasuryAddressRule, treasuryAddressItem)
	}

	logs, sub, err := _Gateway.contract.WatchLogs(opts, "ProtocolAddressUpdated", whatRule, treasuryAddressRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(GatewayProtocolAddressUpdated)
				if err := _Gateway.contract.UnpackLog(event, "ProtocolAddressUpdated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseProtocolAddressUpdated is a log parse operation binding the contract event 0xbbc5b96e57cfecb3dbeeadf92e87f15e58e64fcd75cbe256dcc5d9ef2e51e8a4.
//
// Solidity: event ProtocolAddressUpdated(bytes32 indexed what, address indexed treasuryAddress)
func (_Gateway *GatewayFilterer) ParseProtocolAddressUpdated(log types.Log) (*GatewayProtocolAddressUpdated, error) {
	event := new(GatewayProtocolAddressUpdated)
	if err := _Gateway.contract.UnpackLog(event, "ProtocolAddressUpdated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// GatewaySenderFeeTransferredIterator is returned from FilterSenderFeeTransferred and is used to iterate over the raw logs and unpacked data for SenderFeeTransferred events raised by the Gateway contract.
type GatewaySenderFeeTransferredIterator struct {
	Event *GatewaySenderFeeTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *GatewaySenderFeeTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(GatewaySenderFeeTransferred)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(GatewaySenderFeeTransferred)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *GatewaySenderFeeTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *GatewaySenderFeeTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// GatewaySenderFeeTransferred represents a SenderFeeTransferred event raised by the Gateway contract.
type GatewaySenderFeeTransferred struct {
	OrderId [32]byte
	Sender  common.Address
	Amount  *big.Int
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterSenderFeeTransferred is a free log retrieval operation binding the contract event 0x879f6eb4f1506eb3029982039d90b0e82b07d54f5e911a3c644a974863a98a6c.
//
// Solidity: event SenderFeeTransferred(bytes32 indexed orderId, address indexed sender, uint256 indexed amount)
func (_Gateway *GatewayFilterer) FilterSenderFeeTransferred(opts *bind.FilterOpts, orderId [][32]byte, sender []common.Address, amount []*big.Int) (*GatewaySenderFeeTransferredIterator, error) {

	var orderIdRule []interface{}
	for _, orderIdItem := range orderId {
		orderIdRule = append(orderIdRule, orderIdItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}

	logs, sub, err := _Gateway.contract.FilterLogs(opts, "SenderFeeTransferred", orderIdRule, senderRule, amountRule)
	if err != nil {
		return nil, err
	}
	return &GatewaySenderFeeTransferredIterator{contract: _Gateway.contract, event: "SenderFeeTransferred", logs: logs, sub: sub}, nil
}

// WatchSenderFeeTransferred is a free log subscription operation binding the contract event 0x879f6eb4f1506eb3029982039d90b0e82b07d54f5e911a3c644a974863a98a6c.
//
// Solidity: event SenderFeeTransferred(bytes32 indexed orderId, address indexed sender, uint256 indexed amount)
func (_Gateway *GatewayFilterer) WatchSenderFeeTransferred(opts *bind.WatchOpts, sink chan<- *GatewaySenderFeeTransferred, orderId [][32]byte, sender []common.Address, amount []*big.Int) (event.Subscription, error) {

	var orderIdRule []interface{}
	for _, orderIdItem := range orderId {
		orderIdRule = append(orderIdRule, orderIdItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}

	logs, sub, err := _Gateway.contract.WatchLogs(opts, "SenderFeeTransferred", orderIdRule, senderRule, amountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(GatewaySenderFeeTransferred)
				if err := _Gateway.contract.UnpackLog(event, "SenderFeeTransferred", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseSenderFeeTransferred is a log parse operation binding the contract event 0x879f6eb4f1506eb3029982039d90b0e82b07d54f5e911a3c644a974863a98a6c.
//
// Solidity: event SenderFeeTransferred(bytes32 indexed orderId, address indexed sender, uint256 indexed amount)
func (_Gateway *GatewayFilterer) ParseSenderFeeTransferred(log types.Log) (*GatewaySenderFeeTransferred, error) {
	event := new(GatewaySenderFeeTransferred)
	if err := _Gateway.contract.UnpackLog(event, "SenderFeeTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// GatewaySetFeeRecipientIterator is returned from FilterSetFeeRecipient and is used to iterate over the raw logs and unpacked data for SetFeeRecipient events raised by the Gateway contract.
type GatewaySetFeeRecipientIterator struct {
	Event *GatewaySetFeeRecipient // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *GatewaySetFeeRecipientIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(GatewaySetFeeRecipient)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(GatewaySetFeeRecipient)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *GatewaySetFeeRecipientIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *GatewaySetFeeRecipientIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// GatewaySetFeeRecipient represents a SetFeeRecipient event raised by the Gateway contract.
type GatewaySetFeeRecipient struct {
	TreasuryAddress common.Address
	Raw             types.Log // Blockchain specific contextual infos
}

// FilterSetFeeRecipient is a free log retrieval operation binding the contract event 0x2e979f80fe4d43055c584cf4a8467c55875ea36728fc37176c05acd784eb7a73.
//
// Solidity: event SetFeeRecipient(address indexed treasuryAddress)
func (_Gateway *GatewayFilterer) FilterSetFeeRecipient(opts *bind.FilterOpts, treasuryAddress []common.Address) (*GatewaySetFeeRecipientIterator, error) {

	var treasuryAddressRule []interface{}
	for _, treasuryAddressItem := range treasuryAddress {
		treasuryAddressRule = append(treasuryAddressRule, treasuryAddressItem)
	}

	logs, sub, err := _Gateway.contract.FilterLogs(opts, "SetFeeRecipient", treasuryAddressRule)
	if err != nil {
		return nil, err
	}
	return &GatewaySetFeeRecipientIterator{contract: _Gateway.contract, event: "SetFeeRecipient", logs: logs, sub: sub}, nil
}

// WatchSetFeeRecipient is a free log subscription operation binding the contract event 0x2e979f80fe4d43055c584cf4a8467c55875ea36728fc37176c05acd784eb7a73.
//
// Solidity: event SetFeeRecipient(address indexed treasuryAddress)
func (_Gateway *GatewayFilterer) WatchSetFeeRecipient(opts *bind.WatchOpts, sink chan<- *GatewaySetFeeRecipient, treasuryAddress []common.Address) (event.Subscription, error) {

	var treasuryAddressRule []interface{}
	for _, treasuryAddressItem := range treasuryAddress {
		treasuryAddressRule = append(treasuryAddressRule, treasuryAddressItem)
	}

	logs, sub, err := _Gateway.contract.WatchLogs(opts, "SetFeeRecipient", treasuryAddressRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(GatewaySetFeeRecipient)
				if err := _Gateway.contract.UnpackLog(event, "SetFeeRecipient", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseSetFeeRecipient is a log parse operation binding the contract event 0x2e979f80fe4d43055c584cf4a8467c55875ea36728fc37176c05acd784eb7a73.
//
// Solidity: event SetFeeRecipient(address indexed treasuryAddress)
func (_Gateway *GatewayFilterer) ParseSetFeeRecipient(log types.Log) (*GatewaySetFeeRecipient, error) {
	event := new(GatewaySetFeeRecipient)
	if err := _Gateway.contract.UnpackLog(event, "SetFeeRecipient", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// GatewaySettingManagerBoolIterator is returned from FilterSettingManagerBool and is used to iterate over the raw logs and unpacked data for SettingManagerBool events raised by the Gateway contract.
type GatewaySettingManagerBoolIterator struct {
	Event *GatewaySettingManagerBool // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *GatewaySettingManagerBoolIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(GatewaySettingManagerBool)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(GatewaySettingManagerBool)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *GatewaySettingManagerBoolIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *GatewaySettingManagerBoolIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// GatewaySettingManagerBool represents a SettingManagerBool event raised by the Gateway contract.
type GatewaySettingManagerBool struct {
	What   [32]byte
	Value  common.Address
	Status *big.Int
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterSettingManagerBool is a free log retrieval operation binding the contract event 0xcfa976492af7c14a916cc3a239f4c9c75bbd7f5f0e398beb41d892c7eeccae4c.
//
// Solidity: event SettingManagerBool(bytes32 indexed what, address indexed value, uint256 status)
func (_Gateway *GatewayFilterer) FilterSettingManagerBool(opts *bind.FilterOpts, what [][32]byte, value []common.Address) (*GatewaySettingManagerBoolIterator, error) {

	var whatRule []interface{}
	for _, whatItem := range what {
		whatRule = append(whatRule, whatItem)
	}
	var valueRule []interface{}
	for _, valueItem := range value {
		valueRule = append(valueRule, valueItem)
	}

	logs, sub, err := _Gateway.contract.FilterLogs(opts, "SettingManagerBool", whatRule, valueRule)
	if err != nil {
		return nil, err
	}
	return &GatewaySettingManagerBoolIterator{contract: _Gateway.contract, event: "SettingManagerBool", logs: logs, sub: sub}, nil
}

// WatchSettingManagerBool is a free log subscription operation binding the contract event 0xcfa976492af7c14a916cc3a239f4c9c75bbd7f5f0e398beb41d892c7eeccae4c.
//
// Solidity: event SettingManagerBool(bytes32 indexed what, address indexed value, uint256 status)
func (_Gateway *GatewayFilterer) WatchSettingManagerBool(opts *bind.WatchOpts, sink chan<- *GatewaySettingManagerBool, what [][32]byte, value []common.Address) (event.Subscription, error) {

	var whatRule []interface{}
	for _, whatItem := range what {
		whatRule = append(whatRule, whatItem)
	}
	var valueRule []interface{}
	for _, valueItem := range value {
		valueRule = append(valueRule, valueItem)
	}

	logs, sub, err := _Gateway.contract.WatchLogs(opts, "SettingManagerBool", whatRule, valueRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(GatewaySettingManagerBool)
				if err := _Gateway.contract.UnpackLog(event, "SettingManagerBool", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseSettingManagerBool is a log parse operation binding the contract event 0xcfa976492af7c14a916cc3a239f4c9c75bbd7f5f0e398beb41d892c7eeccae4c.
//
// Solidity: event SettingManagerBool(bytes32 indexed what, address indexed value, uint256 status)
func (_Gateway *GatewayFilterer) ParseSettingManagerBool(log types.Log) (*GatewaySettingManagerBool, error) {
	event := new(GatewaySettingManagerBool)
	if err := _Gateway.contract.UnpackLog(event, "SettingManagerBool", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// GatewaySettleInIterator is returned from FilterSettleIn and is used to iterate over the raw logs and unpacked data for SettleIn events raised by the Gateway contract.
type GatewaySettleInIterator struct {
	Event *GatewaySettleIn // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *GatewaySettleInIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(GatewaySettleIn)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(GatewaySettleIn)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *GatewaySettleInIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *GatewaySettleInIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// GatewaySettleIn represents a SettleIn event raised by the Gateway contract.
type GatewaySettleIn struct {
	OrderId           [32]byte
	LiquidityProvider common.Address
	Recipient         common.Address
	Amount            *big.Int
	Token             common.Address
	AggregatorFee     *big.Int
	Rate              *big.Int
	Raw               types.Log // Blockchain specific contextual infos
}

// FilterSettleIn is a free log retrieval operation binding the contract event 0xb5273ccce1412b056c9246e834895f9d717974c505f8e5a6c7d08cd0300a066b.
//
// Solidity: event SettleIn(bytes32 indexed orderId, address indexed liquidityProvider, address indexed recipient, uint256 amount, address token, uint256 aggregatorFee, uint96 rate)
func (_Gateway *GatewayFilterer) FilterSettleIn(opts *bind.FilterOpts, orderId [][32]byte, liquidityProvider []common.Address, recipient []common.Address) (*GatewaySettleInIterator, error) {

	var orderIdRule []interface{}
	for _, orderIdItem := range orderId {
		orderIdRule = append(orderIdRule, orderIdItem)
	}
	var liquidityProviderRule []interface{}
	for _, liquidityProviderItem := range liquidityProvider {
		liquidityProviderRule = append(liquidityProviderRule, liquidityProviderItem)
	}
	var recipientRule []interface{}
	for _, recipientItem := range recipient {
		recipientRule = append(recipientRule, recipientItem)
	}

	logs, sub, err := _Gateway.contract.FilterLogs(opts, "SettleIn", orderIdRule, liquidityProviderRule, recipientRule)
	if err != nil {
		return nil, err
	}
	return &GatewaySettleInIterator{contract: _Gateway.contract, event: "SettleIn", logs: logs, sub: sub}, nil
}

// WatchSettleIn is a free log subscription operation binding the contract event 0xb5273ccce1412b056c9246e834895f9d717974c505f8e5a6c7d08cd0300a066b.
//
// Solidity: event SettleIn(bytes32 indexed orderId, address indexed liquidityProvider, address indexed recipient, uint256 amount, address token, uint256 aggregatorFee, uint96 rate)
func (_Gateway *GatewayFilterer) WatchSettleIn(opts *bind.WatchOpts, sink chan<- *GatewaySettleIn, orderId [][32]byte, liquidityProvider []common.Address, recipient []common.Address) (event.Subscription, error) {

	var orderIdRule []interface{}
	for _, orderIdItem := range orderId {
		orderIdRule = append(orderIdRule, orderIdItem)
	}
	var liquidityProviderRule []interface{}
	for _, liquidityProviderItem := range liquidityProvider {
		liquidityProviderRule = append(liquidityProviderRule, liquidityProviderItem)
	}
	var recipientRule []interface{}
	for _, recipientItem := range recipient {
		recipientRule = append(recipientRule, recipientItem)
	}

	logs, sub, err := _Gateway.contract.WatchLogs(opts, "SettleIn", orderIdRule, liquidityProviderRule, recipientRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(GatewaySettleIn)
				if err := _Gateway.contract.UnpackLog(event, "SettleIn", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseSettleIn is a log parse operation binding the contract event 0xb5273ccce1412b056c9246e834895f9d717974c505f8e5a6c7d08cd0300a066b.
//
// Solidity: event SettleIn(bytes32 indexed orderId, address indexed liquidityProvider, address indexed recipient, uint256 amount, address token, uint256 aggregatorFee, uint96 rate)
func (_Gateway *GatewayFilterer) ParseSettleIn(log types.Log) (*GatewaySettleIn, error) {
	event := new(GatewaySettleIn)
	if err := _Gateway.contract.UnpackLog(event, "SettleIn", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// GatewaySettleOutIterator is returned from FilterSettleOut and is used to iterate over the raw logs and unpacked data for SettleOut events raised by the Gateway contract.
type GatewaySettleOutIterator struct {
	Event *GatewaySettleOut // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *GatewaySettleOutIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(GatewaySettleOut)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(GatewaySettleOut)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *GatewaySettleOutIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *GatewaySettleOutIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// GatewaySettleOut represents a SettleOut event raised by the Gateway contract.
type GatewaySettleOut struct {
	SplitOrderId      [32]byte
	OrderId           [32]byte
	LiquidityProvider common.Address
	SettlePercent     uint64
	RebatePercent     uint64
	Raw               types.Log // Blockchain specific contextual infos
}

// FilterSettleOut is a free log retrieval operation binding the contract event 0x1e4a1a8ad772d3f0dbb387879bc5e8faadf16e0513bf77d50620741ab92b4c45.
//
// Solidity: event SettleOut(bytes32 splitOrderId, bytes32 indexed orderId, address indexed liquidityProvider, uint64 settlePercent, uint64 rebatePercent)
func (_Gateway *GatewayFilterer) FilterSettleOut(opts *bind.FilterOpts, orderId [][32]byte, liquidityProvider []common.Address) (*GatewaySettleOutIterator, error) {

	var orderIdRule []interface{}
	for _, orderIdItem := range orderId {
		orderIdRule = append(orderIdRule, orderIdItem)
	}
	var liquidityProviderRule []interface{}
	for _, liquidityProviderItem := range liquidityProvider {
		liquidityProviderRule = append(liquidityProviderRule, liquidityProviderItem)
	}

	logs, sub, err := _Gateway.contract.FilterLogs(opts, "SettleOut", orderIdRule, liquidityProviderRule)
	if err != nil {
		return nil, err
	}
	return &GatewaySettleOutIterator{contract: _Gateway.contract, event: "SettleOut", logs: logs, sub: sub}, nil
}

// WatchSettleOut is a free log subscription operation binding the contract event 0x1e4a1a8ad772d3f0dbb387879bc5e8faadf16e0513bf77d50620741ab92b4c45.
//
// Solidity: event SettleOut(bytes32 splitOrderId, bytes32 indexed orderId, address indexed liquidityProvider, uint64 settlePercent, uint64 rebatePercent)
func (_Gateway *GatewayFilterer) WatchSettleOut(opts *bind.WatchOpts, sink chan<- *GatewaySettleOut, orderId [][32]byte, liquidityProvider []common.Address) (event.Subscription, error) {

	var orderIdRule []interface{}
	for _, orderIdItem := range orderId {
		orderIdRule = append(orderIdRule, orderIdItem)
	}
	var liquidityProviderRule []interface{}
	for _, liquidityProviderItem := range liquidityProvider {
		liquidityProviderRule = append(liquidityProviderRule, liquidityProviderItem)
	}

	logs, sub, err := _Gateway.contract.WatchLogs(opts, "SettleOut", orderIdRule, liquidityProviderRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(GatewaySettleOut)
				if err := _Gateway.contract.UnpackLog(event, "SettleOut", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseSettleOut is a log parse operation binding the contract event 0x1e4a1a8ad772d3f0dbb387879bc5e8faadf16e0513bf77d50620741ab92b4c45.
//
// Solidity: event SettleOut(bytes32 splitOrderId, bytes32 indexed orderId, address indexed liquidityProvider, uint64 settlePercent, uint64 rebatePercent)
func (_Gateway *GatewayFilterer) ParseSettleOut(log types.Log) (*GatewaySettleOut, error) {
	event := new(GatewaySettleOut)
	if err := _Gateway.contract.UnpackLog(event, "SettleOut", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// GatewayTokenFeeSettingsUpdatedIterator is returned from FilterTokenFeeSettingsUpdated and is used to iterate over the raw logs and unpacked data for TokenFeeSettingsUpdated events raised by the Gateway contract.
type GatewayTokenFeeSettingsUpdatedIterator struct {
	Event *GatewayTokenFeeSettingsUpdated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *GatewayTokenFeeSettingsUpdatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(GatewayTokenFeeSettingsUpdated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(GatewayTokenFeeSettingsUpdated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *GatewayTokenFeeSettingsUpdatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *GatewayTokenFeeSettingsUpdatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// GatewayTokenFeeSettingsUpdated represents a TokenFeeSettingsUpdated event raised by the Gateway contract.
type GatewayTokenFeeSettingsUpdated struct {
	Token                  common.Address
	SenderToProvider       *big.Int
	ProviderToAggregator   *big.Int
	SenderToAggregator     *big.Int
	ProviderToAggregatorFx *big.Int
	Raw                    types.Log // Blockchain specific contextual infos
}

// FilterTokenFeeSettingsUpdated is a free log retrieval operation binding the contract event 0xd4d646cffa66ebf695b792bd660c97076ed45a889e14d544eb8ab8a44b34a59c.
//
// Solidity: event TokenFeeSettingsUpdated(address indexed token, uint256 senderToProvider, uint256 providerToAggregator, uint256 senderToAggregator, uint256 providerToAggregatorFx)
func (_Gateway *GatewayFilterer) FilterTokenFeeSettingsUpdated(opts *bind.FilterOpts, token []common.Address) (*GatewayTokenFeeSettingsUpdatedIterator, error) {

	var tokenRule []interface{}
	for _, tokenItem := range token {
		tokenRule = append(tokenRule, tokenItem)
	}

	logs, sub, err := _Gateway.contract.FilterLogs(opts, "TokenFeeSettingsUpdated", tokenRule)
	if err != nil {
		return nil, err
	}
	return &GatewayTokenFeeSettingsUpdatedIterator{contract: _Gateway.contract, event: "TokenFeeSettingsUpdated", logs: logs, sub: sub}, nil
}

// WatchTokenFeeSettingsUpdated is a free log subscription operation binding the contract event 0xd4d646cffa66ebf695b792bd660c97076ed45a889e14d544eb8ab8a44b34a59c.
//
// Solidity: event TokenFeeSettingsUpdated(address indexed token, uint256 senderToProvider, uint256 providerToAggregator, uint256 senderToAggregator, uint256 providerToAggregatorFx)
func (_Gateway *GatewayFilterer) WatchTokenFeeSettingsUpdated(opts *bind.WatchOpts, sink chan<- *GatewayTokenFeeSettingsUpdated, token []common.Address) (event.Subscription, error) {

	var tokenRule []interface{}
	for _, tokenItem := range token {
		tokenRule = append(tokenRule, tokenItem)
	}

	logs, sub, err := _Gateway.contract.WatchLogs(opts, "TokenFeeSettingsUpdated", tokenRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(GatewayTokenFeeSettingsUpdated)
				if err := _Gateway.contract.UnpackLog(event, "TokenFeeSettingsUpdated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseTokenFeeSettingsUpdated is a log parse operation binding the contract event 0xd4d646cffa66ebf695b792bd660c97076ed45a889e14d544eb8ab8a44b34a59c.
//
// Solidity: event TokenFeeSettingsUpdated(address indexed token, uint256 senderToProvider, uint256 providerToAggregator, uint256 senderToAggregator, uint256 providerToAggregatorFx)
func (_Gateway *GatewayFilterer) ParseTokenFeeSettingsUpdated(log types.Log) (*GatewayTokenFeeSettingsUpdated, error) {
	event := new(GatewayTokenFeeSettingsUpdated)
	if err := _Gateway.contract.UnpackLog(event, "TokenFeeSettingsUpdated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// GatewayUnpausedIterator is returned from FilterUnpaused and is used to iterate over the raw logs and unpacked data for Unpaused events raised by the Gateway contract.
type GatewayUnpausedIterator struct {
	Event *GatewayUnpaused // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *GatewayUnpausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(GatewayUnpaused)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(GatewayUnpaused)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *GatewayUnpausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *GatewayUnpausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// GatewayUnpaused represents a Unpaused event raised by the Gateway contract.
type GatewayUnpaused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterUnpaused is a free log retrieval operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_Gateway *GatewayFilterer) FilterUnpaused(opts *bind.FilterOpts) (*GatewayUnpausedIterator, error) {

	logs, sub, err := _Gateway.contract.FilterLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return &GatewayUnpausedIterator{contract: _Gateway.contract, event: "Unpaused", logs: logs, sub: sub}, nil
}

// WatchUnpaused is a free log subscription operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_Gateway *GatewayFilterer) WatchUnpaused(opts *bind.WatchOpts, sink chan<- *GatewayUnpaused) (event.Subscription, error) {

	logs, sub, err := _Gateway.contract.WatchLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(GatewayUnpaused)
				if err := _Gateway.contract.UnpackLog(event, "Unpaused", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseUnpaused is a log parse operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_Gateway *GatewayFilterer) ParseUnpaused(log types.Log) (*GatewayUnpaused, error) {
	event := new(GatewayUnpaused)
	if err := _Gateway.contract.UnpackLog(event, "Unpaused", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
