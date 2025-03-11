package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// LockOrderFulfillment holds the schema definition for the LockOrderFulfillment entity.
type LockOrderFulfillment struct {
	ent.Schema
}

// Mixin of the LockOrderFulfillment.
func (LockOrderFulfillment) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the LockOrderFulfillment.
func (LockOrderFulfillment) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New),
		field.String("tx_id").
			Optional(),
		field.String("psp").
			Optional(),
		field.Enum("validation_status").
			Values("pending", "success", "failed").
			Default("pending"),
		field.String("validation_error").
			Optional(),
	}
}

// Edges of the LockOrderFulfillment.
func (LockOrderFulfillment) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("order", LockPaymentOrder.Type).
			Ref("fulfillments").
			Unique().
			Required(),
	}
}
