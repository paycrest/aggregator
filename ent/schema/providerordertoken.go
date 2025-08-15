package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
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
		field.Float("fixed_conversion_rate").
			GoType(decimal.Decimal{}).
			SchemaType(map[string]string{"postgres": "DECIMAL(20,8)"}),
		field.Float("floating_conversion_rate").
			GoType(decimal.Decimal{}).
			SchemaType(map[string]string{"postgres": "DECIMAL(20,8)"}),
		field.Enum("conversion_rate_type").
			Values("fixed", "floating"),
		field.Float("max_order_amount").
			GoType(decimal.Decimal{}).
			SchemaType(map[string]string{"postgres": "DECIMAL(20,8)"}),
		field.Float("min_order_amount").
			GoType(decimal.Decimal{}).
			SchemaType(map[string]string{"postgres": "DECIMAL(20,8)"}),
		field.Float("rate_slippage").
			GoType(decimal.Decimal{}).
			SchemaType(map[string]string{"postgres": "DECIMAL(20,8)"}),
		field.String("address").Optional(),
		field.String("network").Optional(),
	}
}

// Edges of the ProviderOrderToken.
func (ProviderOrderToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("provider", ProviderProfile.Type).
			Ref("order_tokens").
			Required().
			Unique(),
		edge.From("token", Token.Type).
			Ref("provider_order_tokens").
			Required().
			Unique(),
		edge.From("currency", FiatCurrency.Type).
			Ref("provider_order_tokens").
			Required().
			Unique(),
	}
}

// Indexes of the ProviderOrderToken.
func (ProviderOrderToken) Indexes() []ent.Index {
	return []ent.Index{
		// Define a unique index across multiple fields.
		index.Edges("provider", "token", "currency").Unique(),
	}
}
