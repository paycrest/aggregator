package test

import (
	"context"

	"github.com/google/uuid"
	"github.com/paycrest/aggregator/ent"
	"github.com/stretchr/testify/mock"
)

// Mock order service
type MockOrderService struct {
	mock.Mock
}

// ProcessTransfer mocks the ProcessTransfer method
func (m *MockOrderService) ProcessTransfer(ctx context.Context, receiveAddress string, token *ent.Token) error {
	return nil
}

// CreateOrder mocks the CreateOrder method
func (m *MockOrderService) CreateOrder(ctx context.Context, orderID uuid.UUID) error {
	return nil
}

// RefundOrder mocks the RefundOrder method
func (m *MockOrderService) RefundOrder(ctx context.Context, network *ent.Network, orderID string) error {
	return nil
}

// SettleOrder mocks the SettleOrder method
func (m *MockOrderService) SettleOrder(ctx context.Context, orderID uuid.UUID) error {
	return nil
}
