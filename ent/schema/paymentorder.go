package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/ent/hook"
	"github.com/paycrest/aggregator/types"
	"github.com/shopspring/decimal"
)

// PaymentOrder holds the schema definition for the PaymentOrder entity.
type PaymentOrder struct {
	ent.Schema
}

// Mixin of the PaymentOrder.
func (PaymentOrder) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the PaymentOrder.
func (PaymentOrder) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New),
		// Amounts & fees
		field.Float("amount").GoType(decimal.Decimal{}),
		field.Float("rate").GoType(decimal.Decimal{}),
		field.Float("amount_in_usd").GoType(decimal.Decimal{}),
		field.Float("amount_paid").
			GoType(decimal.Decimal{}).
			DefaultFunc(func() decimal.Decimal { return decimal.Zero }),
		field.Float("amount_returned").
			GoType(decimal.Decimal{}).
			DefaultFunc(func() decimal.Decimal { return decimal.Zero }),
		field.Float("percent_settled").
			GoType(decimal.Decimal{}).
			DefaultFunc(func() decimal.Decimal { return decimal.Zero }),
		field.Float("sender_fee").
			GoType(decimal.Decimal{}).
			DefaultFunc(func() decimal.Decimal { return decimal.Zero }),
		field.Float("network_fee").
			GoType(decimal.Decimal{}).
			DefaultFunc(func() decimal.Decimal { return decimal.Zero }),
		field.Float("protocol_fee").
			GoType(decimal.Decimal{}).
			DefaultFunc(func() decimal.Decimal { return decimal.Zero }),
		field.Float("order_percent").
			GoType(decimal.Decimal{}).
			DefaultFunc(func() decimal.Decimal { return decimal.Zero }),
		field.Float("fee_percent").
			GoType(decimal.Decimal{}).
			DefaultFunc(func() decimal.Decimal { return decimal.Zero }),
		// Transaction details
		field.String("tx_hash").
			MaxLen(70).
			Optional(),
		field.Int64("block_number").Default(0),
		field.String("message_hash").
			Optional(),
		field.String("gateway_id").
			MaxLen(255).
			Optional(),
		// Addresses
		field.String("from_address").
			MaxLen(70).
			Optional(),
		field.String("return_address").
			MaxLen(70).
			Optional(),
		field.String("receive_address").
			MaxLen(70).
			Optional().
			Unique(),
		field.Bytes("receive_address_salt").
			Optional(),
		field.Time("receive_address_expiry").
			Optional(),
		field.String("fee_address").
			MaxLen(70).
			Optional(),
		field.Time("indexer_created_at").
			Optional(),
		// Recipient info
		field.String("institution").
			MaxLen(255),
		field.String("account_identifier").
			MaxLen(255),
		field.String("account_name").
			MaxLen(255),
		field.String("memo").
			MaxLen(255).
			Optional(),
		field.JSON("metadata", map[string]interface{}{}).
			Optional(),
		// Order management
		field.String("sender").
			MaxLen(255).
			Optional(),
		field.String("reference").
			MaxLen(70).
			Optional(),
		field.Int("cancellation_count").
			Default(0).
			Optional(),
		field.Strings("cancellation_reasons").
			Default([]string{}).
			Optional(),
		// Status & type
		field.Enum("status").
			Values("initiated", "deposited", "pending", "fulfilling", "fulfilled", "validated", "settling", "settled", "cancelled", "refunding", "refunded", "expired").
			Default("initiated"),
		field.Enum("order_type").
			Values("otc", "regular").
			Default("regular"),
		// Fallback assignment: set when order was assigned via fallback provider (DB-level idempotency).
		field.Time("fallback_tried_at").
			Optional(),
	}
}

// Edges of the PaymentOrder.
func (PaymentOrder) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("token", Token.Type).
			Ref("payment_orders").
			Unique().
			Required(),
		edge.From("sender_profile", SenderProfile.Type).
			Ref("payment_orders").
			Unique(),
		edge.To("payment_webhook", PaymentWebhook.Type).
			Unique(),
		edge.From("provider", ProviderProfile.Type).
			Ref("assigned_orders").
			Unique(),
		edge.From("provision_bucket", ProvisionBucket.Type).
			Ref("payment_orders").
			Unique(),
		edge.To("fulfillments", PaymentOrderFulfillment.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("transactions", TransactionLog.Type),
	}
}

// Indexes of the PaymentOrder.
func (PaymentOrder) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("gateway_id", "rate", "tx_hash", "block_number", "institution", "account_identifier", "account_name", "memo").
			Edges("token").
			Unique(),
	}
}

// Hooks of the PaymentOrder.
func (PaymentOrder) Hooks() []ent.Hook {
	return []ent.Hook{
		// Only run when status is in the mutation (avoids IDs(ctx) when status unchanged).
		hook.If(
			hook.On(types.PaymentOrderDeleteShortIDMappingHook(), ent.OpUpdate|ent.OpUpdateOne),
			hook.HasFields("status"),
		),
	}
}
