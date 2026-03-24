package schema

import (
	"context"
	"fmt"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	gen "github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/hook"
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
		field.UUID("id", uuid.UUID{}).Default(uuid.New).Immutable(),
		field.String("event_type").MaxLen(64).Immutable(),
		field.Float("delta").GoType(decimal.Decimal{}).Immutable(),
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
		index.Edges("payment_order"),
		index.Edges("provider_order_token"),
	}
}

func (ProviderOrderTokenScoreHistory) Hooks() []ent.Hook {
	return []ent.Hook{
		hook.On(
			func(next ent.Mutator) ent.Mutator {
				return hook.ProviderOrderTokenScoreHistoryFunc(func(_ context.Context, m *gen.ProviderOrderTokenScoreHistoryMutation) (ent.Value, error) {
					return nil, fmt.Errorf("provider_order_token_score_histories is append-only: updates are not allowed")
				})
			},
			ent.OpUpdate|ent.OpUpdateOne,
		),
	}
}
