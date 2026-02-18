package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// KYBProfile holds the schema definition for the KYBProfile entity.
type KYBProfile struct {
	ent.Schema
}

func (KYBProfile) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the KYBProfile.
func (KYBProfile) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New),
		field.String("mobile_number"),
		field.String("company_name"),
		field.String("registered_business_address"),
		field.String("daily_estimated_volume").Default(""),
		field.String("certificate_of_incorporation_url"),
		field.String("articles_of_incorporation_url"),
		field.String("business_license_url").
			Optional().
			Nillable(),
		field.String("proof_of_business_address_url"),
		field.String("aml_policy_url").
			Optional(),
		field.String("kyc_policy_url").
			Optional().
			Nillable(),
		field.String("kyb_rejection_comment").
			Optional().
			Nillable(),
	}
}

// Edges of the KYBProfile.
func (KYBProfile) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("beneficial_owners", BeneficialOwner.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.From("user", User.Type).
			Ref("kyb_profile").
			Unique(),
	}
}
