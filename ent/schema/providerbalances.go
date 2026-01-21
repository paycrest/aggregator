package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
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
			Required(),
		edge.From("fiat_currency", FiatCurrency.Type).
			Ref("provider_balances").
			Unique(),
		edge.From("token", Token.Type).
			Ref("provider_balances").
			Unique(),
	}
}

// Indexes of the ProviderBalances.
func (ProviderBalances) Indexes() []ent.Index {
	return nil
}
