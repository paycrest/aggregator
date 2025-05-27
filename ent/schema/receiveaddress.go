package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// ReceiveAddress holds the schema definition for the ReceiveAddress entity.
type ReceiveAddress struct {
	ent.Schema
}

// Mixin of the ReceiveAddress.
func (ReceiveAddress) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the ReceiveAddress.
func (ReceiveAddress) Fields() []ent.Field {
	return []ent.Field{
		field.String("address").Unique(),
		field.Bytes("salt").Unique().Immutable(),
		field.Enum("status").Values("unused", "used", "expired").Default("unused"),
		field.Int64("last_indexed_block").Optional(),
		field.Time("last_used").Optional(),
		field.String("tx_hash").
			MaxLen(70).
			Optional(),
		field.Time("valid_until").Optional(),
        field.String("intent_address").Optional(),
		field.String("intent_network_identifier").Optional(),
		field.String("intent_amount_out").Optional(),
	}
}

// Edges of the ReceiveAddress.
func (ReceiveAddress) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("payment_order", PaymentOrder.Type).
			Ref("receive_address").
			Unique(),
	}
}
