package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// PaymentOrderFulfillment holds the schema definition for the PaymentOrderFulfillment entity.
type PaymentOrderFulfillment struct {
	ent.Schema
}

// Mixin of the PaymentOrderFulfillment.
func (PaymentOrderFulfillment) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the PaymentOrderFulfillment.
func (PaymentOrderFulfillment) Fields() []ent.Field {
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

// Edges of the PaymentOrderFulfillment.
func (PaymentOrderFulfillment) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("order", PaymentOrder.Type).
			Ref("fulfillments").
			Unique().
			Required(),
	}
}
