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

// ProviderBalances holds the schema definition for the ProviderBalances entity.
// Each row is either a fiat balance (offramp) or a token balance (onramp).
// Exactly one of fiat_currency or token must be set (enforced by CHECK constraint).
type ProviderBalances struct {
	ent.Schema
}

// Fields of the ProviderBalances.
func (ProviderBalances) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New),
		field.Float("available_balance").GoType(decimal.Decimal{}),
		field.Float("total_balance").GoType(decimal.Decimal{}),
		field.Float("reserved_balance").GoType(decimal.Decimal{}),
		field.Bool("is_available").Default(true),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

// Edges of the ProviderBalances.
func (ProviderBalances) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("provider", ProviderProfile.Type).
			Ref("provider_balances").
			Required().
			Unique(), // O2M: each balance belongs to exactly one provider
		edge.From("fiat_currency", FiatCurrency.Type).
			Ref("provider_balances").
			Unique(),
		edge.From("token", Token.Type).
			Ref("provider_balances").
			Unique(),
	}
}

// Indexes of the ProviderBalances.
// Composite unique indexes ensure a provider can only have one balance per currency/token.
func (ProviderBalances) Indexes() []ent.Index {
	return []ent.Index{
		// Unique constraint: one fiat balance per provider per currency
		index.Edges("provider", "fiat_currency").Unique(),
		// Unique constraint: one token balance per provider per token
		index.Edges("provider", "token").Unique(),
	}
}
