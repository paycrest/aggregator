package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// PaymentOrderRecipient holds the schema definition for the PaymentOrderRecipient entity.
type PaymentOrderRecipient struct {
	ent.Schema
}

// Fields of the PaymentOrderRecipient.
func (PaymentOrderRecipient) Fields() []ent.Field {
	return []ent.Field{
		field.String("institution"),
		field.String("account_identifier"),
		field.String("account_name"),
		field.String("memo").
			Optional(),
		field.String("provider_id").
			Optional(),
		field.JSON("metadata", map[string]interface{}{}).
			Optional(),
	}
}

// Edges of the PaymentOrderRecipient.
func (PaymentOrderRecipient) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("payment_order", PaymentOrder.Type).
			Ref("recipient").
			Unique().
			Required(),
	}
}
