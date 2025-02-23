package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/shopspring/decimal"
)

// ProviderOrderToken holds the schema definition for the ProviderOrderToken entity.
type ProviderOrderToken struct {
	ent.Schema
}

// Mixin of the ProviderOrderToken.
func (ProviderOrderToken) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the ProviderOrderToken.
func (ProviderOrderToken) Fields() []ent.Field {
	return []ent.Field{
		field.String("symbol"),
		field.Float("fixed_conversion_rate").
			GoType(decimal.Decimal{}),
		field.Float("floating_conversion_rate").
			GoType(decimal.Decimal{}),
		field.Enum("conversion_rate_type").
			Values("fixed", "floating"),
		field.Float("max_order_amount").
			GoType(decimal.Decimal{}),
		field.Float("min_order_amount").
			GoType(decimal.Decimal{}),
		field.Float("rate_slippage").
			GoType(decimal.Decimal{}).
			Optional(),
		field.JSON("addresses", []struct {
			Address string `json:"address"`
			Network string `json:"network"`
		}{}),
	}
}

// Edges of the ProviderOrderToken.
func (ProviderOrderToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("provider", ProviderProfile.Type).
			Ref("order_tokens").
			Unique(),
	}
}

// Indexes of the ProviderOrderToken.
func (ProviderOrderToken) Indexes() []ent.Index {
	return nil
}
