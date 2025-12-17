package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/shopspring/decimal"
)

// ProviderRating holds the schema definition for the ProviderRating entity.
type ProviderRating struct {
	ent.Schema
}

// Mixin of the ProviderRating.
func (ProviderRating) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the ProviderRating.
func (ProviderRating) Fields() []ent.Field {
	return []ent.Field{
		field.Float("trust_score").
			GoType(decimal.Decimal{}),
	}
}

// Edges of the ProviderRating.
func (ProviderRating) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("provider_profile", ProviderProfile.Type).
			Ref("provider_rating").
			Unique().
			Required().
			Immutable(),
	}
}
