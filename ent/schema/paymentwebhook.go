package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// PaymentWebhook holds the schema definition for the PaymentWebhook entity.
type PaymentWebhook struct {
	ent.Schema
}

// Mixin of the PaymentWebhook.
func (PaymentWebhook) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the PaymentWebhook.
func (PaymentWebhook) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New),
		field.String("webhook_id").
			MaxLen(100).
			NotEmpty(),
		field.String("webhook_secret").
			MaxLen(100).
			NotEmpty(),
		field.String("callback_url").
			MaxLen(255).
			NotEmpty(),
	}
}

// Edges of the PaymentWebhook.
func (PaymentWebhook) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("payment_order", PaymentOrder.Type).
			Ref("payment_webhook").
			Unique(),
	}
}
