package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// TransactionLog holds the schema definition for the TransactionLog entity.
type TransactionLog struct {
	ent.Schema
}

// Fields of the TransactionLog.
func (TransactionLog) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.String("gateway_id").Optional(),
		field.Enum("status").
			Values("order_initiated", "crypto_deposited", "order_created", "order_fulfilling", "order_fulfilled", "order_validated", "order_settling", "order_settled", "order_refunding", "order_refunded", "gas_prefunded", "gateway_approved").
			Default("order_initiated").
			Immutable(),
		field.String("network").Optional(),
		field.String("tx_hash").Optional(),
		field.Time("created_at").Default(time.Now).Immutable(),
	}
}

// Edges of the TransactionLog.
func (TransactionLog) Edges() []ent.Edge {
	return nil
}
