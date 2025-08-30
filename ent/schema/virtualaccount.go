package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/shopspring/decimal"
)

// VirtualAccount holds the schema definition for the VirtualAccount entity.
type VirtualAccount struct {
	ent.Schema
}

// Mixin of the VirtualAccount.
func (VirtualAccount) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the VirtualAccount.
func (VirtualAccount) Fields() []ent.Field {
	return []ent.Field{
		field.Float("amount").GoType(decimal.Decimal{}),
		field.String("currency").
			MaxLen(20),
		field.String("institution_name").
			MaxLen(20),
		field.String("account_identifier").
			MaxLen(20),
		field.String("account_name"),
		field.String("valid_until").
			Optional(),
		field.String("provider_eoa").
			MaxLen(20),
		field.Enum("status").
			Values("unused", "expired", "used").
			Default("unused"),
		field.JSON("metadata", map[string]interface{}{}).
			Optional(),
	}
}

// Edges of the VirtualAccount.
func (VirtualAccount) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("payment_order", PaymentOrder.Type).
            Ref("virtual_account").
            Unique(),
		edge.From("provider", ProviderProfile.Type).
			Ref("virtual_accounts").
			Unique(),
	}
}
