package balance

import (
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/storage"
)

// Service handles provider balance operations.
type Service struct {
	client *ent.Client
}

// New creates a new instance of Service.
func New() *Service {
	return &Service{
		client: storage.GetClient(),
	}
}

// NewWithClient creates a new Service using the provided ent client.
// Useful for tests.
func NewWithClient(client *ent.Client) *Service {
	return &Service{client: client}
}
