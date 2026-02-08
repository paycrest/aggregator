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
		field.Float("fixed_buy_rate").
			GoType(decimal.Decimal{}).
			Optional(),
		field.Float("fixed_sell_rate").
			GoType(decimal.Decimal{}).
			Optional(),
		field.Float("floating_buy_delta").
			GoType(decimal.Decimal{}).
			Optional(),
		field.Float("floating_sell_delta").
			GoType(decimal.Decimal{}).
			Optional(),
		field.Float("max_order_amount").
			GoType(decimal.Decimal{}),
		field.Float("min_order_amount").
			GoType(decimal.Decimal{}),
		field.Float("max_order_amount_otc").
			GoType(decimal.Decimal{}),
		field.Float("min_order_amount_otc").
			GoType(decimal.Decimal{}),
		field.Float("rate_slippage").
			GoType(decimal.Decimal{}),
		field.String("settlement_address").Optional(),
		field.String("payout_address").Optional(),
		field.String("network"),
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
		// Define a unique index across multiple fields including network.
		index.Edges("provider", "token", "currency").Fields("network").Unique(),
	}
}
