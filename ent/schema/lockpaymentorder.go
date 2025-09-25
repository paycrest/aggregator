package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// LockPaymentOrder holds the schema definition for the LockPaymentOrder entity.
type LockPaymentOrder struct {
	ent.Schema
}

// Mixin of the LockPaymentOrder.
func (LockPaymentOrder) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the LockPaymentOrder.
func (LockPaymentOrder) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New),
		field.String("gateway_id"),
		field.Float("amount").
			GoType(decimal.Decimal{}),
		field.Float("protocol_fee").
			GoType(decimal.Decimal{}),
		field.Float("rate").
			GoType(decimal.Decimal{}),
		field.Float("order_percent").
			GoType(decimal.Decimal{}),
		field.String("sender").Optional(),
		field.String("tx_hash").
			MaxLen(70).
			Optional(),
		field.Enum("status").
			Values("pending", "processing", "cancelled", "fulfilled", "validated", "settled", "refunded").
			Default("pending"),
		field.Int64("block_number"),
		field.String("institution"),
		field.String("account_identifier"),
		field.String("account_name"),
		field.String("memo").
			Optional(),
		field.JSON("metadata", map[string]interface{}{}).
			Optional(),
		field.Int("cancellation_count").
			Default(0),
		field.Strings("cancellation_reasons").
			Default([]string{}),
		field.String("message_hash").
			MaxLen(400).
			Optional(),
	}
}

// Edges of the LockPaymentOrder.
func (LockPaymentOrder) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("token", Token.Type).
			Ref("lock_payment_orders").
			Unique().
			Required(),
		edge.From("provision_bucket", ProvisionBucket.Type).
			Ref("lock_payment_orders").
			Unique(),
		edge.From("provider", ProviderProfile.Type).
			Ref("assigned_orders").
			Unique(),
		edge.To("fulfillments", LockOrderFulfillment.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("transactions", TransactionLog.Type),
	}
}

// Indexes of the LockPaymentOrder.
func (LockPaymentOrder) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("gateway_id", "rate", "tx_hash", "block_number", "institution", "account_identifier", "account_name", "memo").
			Edges("token").
			Unique(),
	}
}
