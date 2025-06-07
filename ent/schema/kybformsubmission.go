package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// BeneficialOwner holds the schema definition for the BeneficialOwner entity.
type BeneficialOwner struct {
	ent.Schema
}

// Fields of the BeneficialOwner.
func (BeneficialOwner) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New),
		field.String("full_name").
			MaxLen(160),
		field.String("residential_address"),
		field.String("proof_of_residential_address_url"),
		field.String("government_issued_id_url"),
		field.String("date_of_birth"),
		field.Float("ownership_percentage"),
	}
}

// Edges of the BeneficialOwner.
func (BeneficialOwner) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("kyb_form_submission", KYBFormSubmission.Type).
			Ref("beneficial_owners").
			Unique(),
	}
}

// KYBFormSubmission holds the schema definition for the KYBFormSubmission entity.
type KYBFormSubmission struct {
	ent.Schema
}

// Mixin of the KYBFormSubmission.
func (KYBFormSubmission) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the KYBFormSubmission.
func (KYBFormSubmission) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New),
		field.String("email"),
		field.String("company_name"),
		field.String("registered_business_address"),
		field.String("certificate_of_incorporation_url"),
		field.String("articles_of_incorporation_url"),
		field.String("business_license_url").
			Optional().
			Nillable(),
		field.String("proof_of_business_address_url"),
		field.String("proof_of_residential_address_url"),
		field.String("aml_policy_url").
			Optional().
			Nillable(),
		field.String("kyc_policy_url").
			Optional().
			Nillable(),
	}
}

// Edges of the KYBFormSubmission.
func (KYBFormSubmission) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("beneficial_owners", BeneficialOwner.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("user", User.Type).
			Unique().
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}
