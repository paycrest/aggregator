package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// ProviderOrderTokenScoreHistory is append-only; unique (payment_order edge + event_type) enforces idempotent scoring.
// FKs cascade: deleting a payment_order or provider_order_token removes related score history rows.
type ProviderOrderTokenScoreHistory struct {
	ent.Schema
}

func (ProviderOrderTokenScoreHistory) Mixin() []ent.Mixin {
	return []ent.Mixin{TimeMixin{}}
}

func (ProviderOrderTokenScoreHistory) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New),
		field.String("event_type").MaxLen(64),
		field.Float("delta").GoType(decimal.Decimal{}),
	}
}

func (ProviderOrderTokenScoreHistory) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("payment_order", PaymentOrder.Type).
			Ref("provider_order_token_score_histories").
			Unique().
			Required(),
		edge.From("provider_order_token", ProviderOrderToken.Type).
			Ref("score_histories").
			Unique().
			Required(),
	}
}

func (ProviderOrderTokenScoreHistory) Indexes() []ent.Index {
	return []ent.Index{
		index.Edges("payment_order").Fields("event_type").Unique(),
	}
}
