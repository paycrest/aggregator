package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// ProvisionBucket is legacy; Phase 1 removes all Ent edges. Table/columns may remain until Phase 2 migration.
type ProvisionBucket struct {
	ent.Schema
}

func (ProvisionBucket) Fields() []ent.Field {
	return []ent.Field{
		field.Float("min_amount").
			GoType(decimal.Decimal{}),
		field.Float("max_amount").
			GoType(decimal.Decimal{}),
		field.Time("created_at").
			Immutable().
			Default(time.Now),
		field.UUID("fiat_currency_id", uuid.UUID{}).
			Optional().
			Nillable().
			StorageKey("fiat_currency_provision_buckets"),
	}
}

func (ProvisionBucket) Edges() []ent.Edge {
	return nil
}
