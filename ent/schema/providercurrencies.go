package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// ProviderCurrencies holds the schema definition for the ProviderCurrencies entity.
type ProviderCurrencies struct {
	ent.Schema
}

// Fields of the ProviderCurrencies.
func (ProviderCurrencies) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New),
		field.Float("available_balance").
			GoType(decimal.Decimal{}),
		field.Float("total_balance").
			GoType(decimal.Decimal{}),
		field.Float("reserved_balance").
			GoType(decimal.Decimal{}),
		field.Bool("is_available").
			Default(true),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Edges of the ProviderCurrencies.
func (ProviderCurrencies) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("provider", ProviderProfile.Type).
			Ref("provider_currencies").
			Required().
			Unique(),
		edge.From("currency", FiatCurrency.Type).
			Ref("provider_currencies").
			Required().
			Unique(),
	}
}

// Indexes of the ProviderCurrencies.
func (ProviderCurrencies) Indexes() []ent.Index {
	return []ent.Index{
		// Unique constraint on provider + currency combination
		index.Edges("provider", "currency").Unique(),
	}
}
