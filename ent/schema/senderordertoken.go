package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/shopspring/decimal"
)

// SenderOrderToken holds the schema definition for the SenderOrderToken entity.
type SenderOrderToken struct {
	ent.Schema
}

// Mixin of the Token.
func (SenderOrderToken) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the SenderOrderToken.
func (SenderOrderToken) Fields() []ent.Field {
	return []ent.Field{
		field.Float("fee_percent").
			GoType(decimal.Decimal{}),
		field.Float("max_fee_cap").
			GoType(decimal.Decimal{}).
			Optional().
			Nillable(),
		field.String("fee_address").MaxLen(60),
		field.String("refund_address").MaxLen(60),
	}
}

// Edges of the SenderOrderToken.
func (SenderOrderToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("sender", SenderProfile.Type).
			Ref("order_tokens").
			Required().
			Unique(),
		edge.From("token", Token.Type).
			Ref("sender_order_tokens").
			Required().
			Unique(),
	}
}

// Indexes of the SenderOrderToken.
func (SenderOrderToken) Indexes() []ent.Index {
	return []ent.Index{
		// Define a unique index across multiple fields.
		index.Edges("sender", "token").Unique(),
	}
}
