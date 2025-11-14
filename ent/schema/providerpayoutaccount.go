package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// ProviderPayoutAccount holds the schema definition for the ProviderPayoutAccount entity.
type ProviderPayoutAccount struct {
	ent.Schema
}

// Fields of the ProviderPayoutAccount.
func (ProviderPayoutAccount) Fields() []ent.Field {
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
			Optional(),
		field.Time("created_at").
			Default(time.Now),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Edges of the ProviderPayoutAccount.
func (ProviderPayoutAccount) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("provider", ProviderProfile.Type).
			Ref("provider_payout_accounts").
			Unique().
			Required().
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}
