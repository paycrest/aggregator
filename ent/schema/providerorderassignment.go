package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// ProviderOrderAssignment holds the schema definition for assignment history (assigned / reassigned).
type ProviderOrderAssignment struct {
	ent.Schema
}

// Fields of the ProviderOrderAssignment.
func (ProviderOrderAssignment) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New).Immutable(),
		field.Enum("assignment_status").
			Values("assigned", "reassigned", "accepted").
			Default("assigned"),
		field.Time("assigned_at").
			Default(time.Now),
		field.Time("reassigned_at").
			Optional(),
	}
}

// Edges of the ProviderOrderAssignment.
func (ProviderOrderAssignment) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("payment_order", PaymentOrder.Type).
			Ref("provider_assignments").
			Unique().
			Required(),
		edge.From("provider", ProviderProfile.Type).
			Ref("order_assignments").
			Unique().
			Required(),
	}
}

// Indexes of the ProviderOrderAssignment.
func (ProviderOrderAssignment) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("assignment_status"),
		index.Edges("payment_order", "provider").Unique(),
	}
}
