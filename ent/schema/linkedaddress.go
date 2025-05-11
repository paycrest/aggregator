package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// LinkedAddress holds the schema definition for the LinkedAddress entity.
type LinkedAddress struct {
	ent.Schema
}

// Mixin of the LinkedAddress.
func (LinkedAddress) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the LinkedAddress.
func (LinkedAddress) Fields() []ent.Field {
	return []ent.Field{
		field.String("address").
			Unique(),
		field.Bytes("salt").
			Unique().
			Immutable(),
		field.String("institution"),
		field.String("account_identifier"),
		field.String("account_name"),
		field.JSON("metadata", map[string]interface{}{}).
			Optional(),
		field.String("owner_address").
			Unique(),
		field.Int64("last_indexed_block").
			Optional(),
		field.String("tx_hash").
			MaxLen(70).
			Optional(),
	}
}

// Edges of the LinkedAddress.
func (LinkedAddress) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("payment_orders", PaymentOrder.Type).
			Annotations(entsql.OnDelete(entsql.SetNull)),
	}
}
