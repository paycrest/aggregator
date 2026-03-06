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
		field.Enum("government_issued_id_type").
			Values("passport", "drivers_license", "national_id").
			Optional(),
	}
}

// Edges of the BeneficialOwner.
func (BeneficialOwner) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("kyb_profile", KYBProfile.Type).
			Ref("beneficial_owners").
			Required().
			Unique().
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}
