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
	ABI: "[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"senderAmount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"aggregatorAmount\",\"type\":\"uint256\"}],\"name\":\"FxTransferFeeSplit\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint8\",\"name\":\"version\",\"type\":\"uint8\"}],\"name\":\"Initialized\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"senderAmount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"providerAmount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"aggregatorAmount\",\"type\":\"uint256\"}],\"name\":\"LocalTransferFeeSplit\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"token\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"protocolFee\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"rate\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"string\",\"name\":\"messageHash\",\"type\":\"string\"}],\"name\":\"OrderCreated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"fee\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"}],\"name\":\"OrderRefunded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferStarted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferred\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"Paused\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"what\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"treasuryAddress\",\"type\":\"address\"}],\"name\":\"ProtocolAddressUpdated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"SenderFeeTransferred\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"treasuryAddress\",\"type\":\"address\"}],\"name\":\"SetFeeRecipient\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"what\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"value\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"status\",\"type\":\"uint256\"}],\"name\":\"SettingManagerBool\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"token\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"aggregatorFee\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint96\",\"name\":\"rate\",\"type\":\"uint96\"}],\"name\":\"SettleIn\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"splitOrderId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"liquidityProvider\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint64\",\"name\":\"settlePercent\",\"type\":\"uint64\"},{\"indexed\":false,\"internalType\":\"uint64\",\"name\":\"rebatePercent\",\"type\":\"uint64\"}],\"name\":\"SettleOut\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"token\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"senderToProvider\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"providerToAggregator\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"senderToAggregator\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"providerToAggregatorFx\",\"type\":\"uint256\"}],\"name\":\"TokenFeeSettingsUpdated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"Unpaused\",\"type\":\"event\"},{\"inputs\":[],\"name\":\"acceptOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_token\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_amount\",\"type\":\"uint256\"},{\"internalType\":\"uint96\",\"name\":\"_rate\",\"type\":\"uint96\"},{\"internalType\":\"address\",\"name\":\"_senderFeeRecipient\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_senderFee\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"_refundAddress\",\"type\":\"address\"},{\"internalType\":\"string\",\"name\":\"messageHash\",\"type\":\"string\"}],\"name\":\"createOrder\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getAggregator\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"_orderId\",\"type\":\"bytes32\"}],\"name\":\"getOrderInfo\",\"outputs\":[{\"components\":[{\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"token\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"senderFeeRecipient\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"senderFee\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"protocolFee\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"isFulfilled\",\"type\":\"bool\"},{\"internalType\":\"bool\",\"name\":\"isRefunded\",\"type\":\"bool\"},{\"internalType\":\"address\",\"name\":\"refundAddress\",\"type\":\"address\"},{\"internalType\":\"uint96\",\"name\":\"currentBPS\",\"type\":\"uint96\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"internalType\":\"structIGateway.Order\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"token\",\"type\":\"address\"}],\"name\":\"getTokenFeeSettings\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"senderToProvider\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"providerToAggregator\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"senderToAggregator\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"providerToAggregatorFx\",\"type\":\"uint256\"}],\"internalType\":\"structGatewaySettingManager.TokenFeeSettings\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"initialize\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_token\",\"type\":\"address\"}],\"name\":\"isTokenSupported\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"pause\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"paused\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"pendingOwner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_fee\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"_orderId\",\"type\":\"bytes32\"}],\"name\":\"refund\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"renounceOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"token\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"senderToProvider\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"providerToAggregator\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"senderToAggregator\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"providerToAggregatorFx\",\"type\":\"uint256\"}],\"name\":\"setTokenFeeSettings\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"what\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"value\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"status\",\"type\":\"uint256\"}],\"name\":\"settingManagerBool\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"_orderId\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"_token\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_amount\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"_senderFeeRecipient\",\"type\":\"address\"},{\"internalType\":\"uint96\",\"name\":\"_senderFee\",\"type\":\"uint96\"},{\"internalType\":\"address\",\"name\":\"_recipient\",\"type\":\"address\"},{\"internalType\":\"uint96\",\"name\":\"_rate\",\"type\":\"uint96\"}],\"name\":\"settleIn\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"_splitOrderId\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"_orderId\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"_liquidityProvider\",\"type\":\"address\"},{\"internalType\":\"uint64\",\"name\":\"_settlePercent\",\"type\":\"uint64\"},{\"internalType\":\"uint64\",\"name\":\"_rebatePercent\",\"type\":\"uint64\"}],\"name\":\"settleOut\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"unpause\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"what\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"value\",\"type\":\"address\"}],\"name\":\"updateProtocolAddress\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
}

// GatewayABI is the input ABI used to generate the binding from.
// Deprecated: Use GatewayMetaData.ABI instead.
var GatewayABI = GatewayMetaData.ABI

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
	Contract     *Gateway        // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// GatewayCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type GatewayCallerSession struct {
	Contract *GatewayCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts    // Call options to use throughout this session
}

// GatewayTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type GatewayTransactorSession struct {
	Contract     *GatewayTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts    // Transaction auth options to use throughout this session
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
	OrderId       [32]byte
	Amount        *big.Int
	Recipient     common.Address
	Token         common.Address
	AggregatorFee *big.Int
	Rate          *big.Int
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterSettleIn is a free log retrieval operation binding the contract event 0x44de25d68888fdbe51bc67bbc990724fb5fa28119062e5f4ca623aefcaa70ecb.
//
// Solidity: event SettleIn(bytes32 indexed orderId, uint256 indexed amount, address indexed recipient, address token, uint256 aggregatorFee, uint96 rate)
func (_Gateway *GatewayFilterer) FilterSettleIn(opts *bind.FilterOpts, orderId [][32]byte, amount []*big.Int, recipient []common.Address) (*GatewaySettleInIterator, error) {

	var orderIdRule []interface{}
	for _, orderIdItem := range orderId {
		orderIdRule = append(orderIdRule, orderIdItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}
	var recipientRule []interface{}
	for _, recipientItem := range recipient {
		recipientRule = append(recipientRule, recipientItem)
	}

	logs, sub, err := _Gateway.contract.FilterLogs(opts, "SettleIn", orderIdRule, amountRule, recipientRule)
	if err != nil {
		return nil, err
	}
	return &GatewaySettleInIterator{contract: _Gateway.contract, event: "SettleIn", logs: logs, sub: sub}, nil
}

// WatchSettleIn is a free log subscription operation binding the contract event 0x44de25d68888fdbe51bc67bbc990724fb5fa28119062e5f4ca623aefcaa70ecb.
//
// Solidity: event SettleIn(bytes32 indexed orderId, uint256 indexed amount, address indexed recipient, address token, uint256 aggregatorFee, uint96 rate)
func (_Gateway *GatewayFilterer) WatchSettleIn(opts *bind.WatchOpts, sink chan<- *GatewaySettleIn, orderId [][32]byte, amount []*big.Int, recipient []common.Address) (event.Subscription, error) {

	var orderIdRule []interface{}
	for _, orderIdItem := range orderId {
		orderIdRule = append(orderIdRule, orderIdItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}
	var recipientRule []interface{}
	for _, recipientItem := range recipient {
		recipientRule = append(recipientRule, recipientItem)
	}

	logs, sub, err := _Gateway.contract.WatchLogs(opts, "SettleIn", orderIdRule, amountRule, recipientRule)
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

// ParseSettleIn is a log parse operation binding the contract event 0x44de25d68888fdbe51bc67bbc990724fb5fa28119062e5f4ca623aefcaa70ecb.
//
// Solidity: event SettleIn(bytes32 indexed orderId, uint256 indexed amount, address indexed recipient, address token, uint256 aggregatorFee, uint96 rate)
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
