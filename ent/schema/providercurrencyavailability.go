package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// ProviderCurrencyAvailability holds the schema definition for the ProviderCurrencyAvailability entity.
type ProviderCurrencyAvailability struct {
	ent.Schema
}

// Fields of the ProviderCurrencyAvailability.
func (ProviderCurrencyAvailability) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New),
		field.Bool("is_available").Default(true),
	}
}

// Edges of the ProviderCurrencyAvailability.
func (ProviderCurrencyAvailability) Edges() []ent.Edge {
	return []ent.Edge{
		// Foreign key to ProviderProfile
		edge.From("provider", ProviderProfile.Type).
			Ref("currency_availability").
			Unique().
			Required(),
		// Foreign key to FiatCurrency
		edge.From("currency", FiatCurrency.Type).
			Ref("provider_availability").
			Unique().
			Required(),
	}
}
