package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// SenderFiatAccount holds fiat bank details used as onramp refund accounts for a sender.
type SenderFiatAccount struct {
	ent.Schema
}

// Mixin of the SenderFiatAccount.
func (SenderFiatAccount) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the SenderFiatAccount.
func (SenderFiatAccount) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New),
		field.String("institution").
			MaxLen(100).
			NotEmpty(),
		field.String("account_identifier").
			MaxLen(200).
			NotEmpty(),
		field.String("account_name").
			MaxLen(200).
			NotEmpty(),
	}
}

// Edges of the SenderFiatAccount.
func (SenderFiatAccount) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("sender", SenderProfile.Type).
			Ref("refund_accounts").
			Unique().
			Required().
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

// Indexes of the SenderFiatAccount (unique per sender + institution + account id).
func (SenderFiatAccount) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("institution", "account_identifier").
			Edges("sender").
			Unique(),
		// List/delete by sender (WHERE sender_profile_refund_accounts = ?).
		index.Edges("sender"),
	}
}
