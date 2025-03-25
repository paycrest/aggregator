package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// FiatCurrency holds the schema definition for the FiatCurrency entity.
type FiatCurrency struct {
	ent.Schema
}

// Mixin of the FiatCurrency.
func (FiatCurrency) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the FiatCurrency.
func (FiatCurrency) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New),
		field.String("code").Unique(), // https://en.wikipedia.org/wiki/ISO_4217
		field.String("short_name").Unique(),
		field.Int("decimals").Default(2),
		field.String("symbol"),
		field.String("name"),
		field.Float("market_rate").
			GoType(decimal.Decimal{}),
		field.Bool("is_enabled").Default(false),
	}
}

// Edges of the FiatCurrency.
func (FiatCurrency) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("providers", ProviderProfile.Type),
		edge.To("provision_buckets", ProvisionBucket.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("institutions", Institution.Type),
		edge.To("provider_order_tokens", ProviderOrderToken.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("provider_availability", ProviderCurrencyAvailability.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}
