package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Token holds the schema definition for the Token entity.
type Token struct {
	ent.Schema
}

// Mixin of the Token.
func (Token) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the Token.
func (Token) Fields() []ent.Field {
	return []ent.Field{
		field.String("symbol").MaxLen((10)),
		field.String("contract_address").MaxLen(60),
		field.Int8("decimals"),
		field.Bool("is_enabled").Default(false),
		field.String("base_currency").Default("USD"),
	}
}

// Edges of the Token.
func (Token) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("network", Network.Type).
			Ref("tokens").
			Required().
			Unique(),
		edge.To("payment_orders", PaymentOrder.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("lock_payment_orders", LockPaymentOrder.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("sender_order_tokens", SenderOrderToken.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("provider_order_tokens", ProviderOrderToken.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}
