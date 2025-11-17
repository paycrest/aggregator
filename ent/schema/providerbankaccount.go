package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// ProviderBankAccount holds the schema definition for the ProviderBankAccount entity.
type ProviderBankAccount struct {
	ent.Schema
}

// Fields of the ProviderBankAccount.
func (ProviderBankAccount) Fields() []ent.Field {
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

// Edges of the ProviderBankAccount.
func (ProviderBankAccount) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("provider", ProviderProfile.Type).
			Ref("provider_bank_accounts").
			Unique().
			Required().
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

// Indexes of the ProviderBankAccount (enforces uniqueness per AC #2).
func (ProviderBankAccount) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("institution", "account_identifier").
			Edges("provider").
			Unique(),
	}
}