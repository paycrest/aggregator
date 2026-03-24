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

// ProviderAssignmentRun records one assignment attempt for audit. FKs cascade on payment_order / provider_order_token delete.
type ProviderAssignmentRun struct {
	ent.Schema
}

func (ProviderAssignmentRun) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New),
		field.String("assigned_provider_id").MaxLen(255).Optional().Nillable(),
		field.Time("attempted_at").Default(time.Now),
		field.String("trigger").MaxLen(64),
		field.String("result").MaxLen(32),
		field.Bool("used_fallback").Default(false),
		field.Float("market_buy_rate_snapshot").GoType(decimal.Decimal{}).Optional().Nillable(),
		field.Float("market_sell_rate_snapshot").GoType(decimal.Decimal{}).Optional().Nillable(),
		field.Text("error_message").Optional().Nillable(),
	}
}

func (ProviderAssignmentRun) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("payment_order", PaymentOrder.Type).
			Ref("provider_assignment_runs").
			Unique().
			Required(),
		edge.From("provider_order_token", ProviderOrderToken.Type).
			Ref("assignment_runs").
			Unique(),
	}
}

func (ProviderAssignmentRun) Indexes() []ent.Index {
	return []ent.Index{
		index.Edges("payment_order"),
		index.Edges("provider_order_token"),
	}
}
