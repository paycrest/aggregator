package schema

import (
	"hash/maphash"
	"math/rand"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// ProviderProfile holds the schema definition for the ProviderProfile entity.
type ProviderProfile struct {
	ent.Schema
}

// Fields of the ProviderProfile.
func (ProviderProfile) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			DefaultFunc(generateProviderID).
			Unique(),
		field.String("trading_name").MaxLen(80).Optional(),
		field.String("host_identifier").
			Optional(),
		field.Enum("provision_mode").
			Values("manual", "auto").
			Default("auto"),
		field.Bool("is_active").
			Default(false),
		field.Bool("is_kyb_verified").
			Default(false),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
		field.Enum("visibility_mode").
			Values("private", "public").
			Default("public"),
	}
}

// Edges of the ProviderProfile.
func (ProviderProfile) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("provider_profile").
			Unique().
			Required().
			Immutable(),
		edge.To("api_key", APIKey.Type).
			Unique().
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("provider_currencies", ProviderCurrencies.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.From("provision_buckets", ProvisionBucket.Type).
			Ref("provider_profiles"),
		edge.To("order_tokens", ProviderOrderToken.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("assigned_orders", PaymentOrder.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("fiat_accounts", ProviderFiatAccount.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

// generateProviderID generates a random string of the specified length
func generateProviderID() string {
	// Define the character set for the random string
	charset := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

	// Create a random string of 8 characters
	r := rand.New(rand.NewSource(int64(new(maphash.Hash).Sum64())))

	b := make([]byte, 8)
	for i := range b {
		b[i] = charset[r.Intn(len(charset))]
	}

	return string(b)
}
