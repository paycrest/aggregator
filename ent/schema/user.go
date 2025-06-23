package schema

import (
	"context"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	gen "github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/hook"
	"golang.org/x/crypto/bcrypt"
)

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

// Mixin of the User.
func (User) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the User.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New),
		field.String("first_name").MaxLen(80),
		field.String("last_name").MaxLen(80),
		field.String("email").
			Unique(),
		field.String("password").Sensitive(),
		field.String("scope"),
		field.Bool("is_email_verified").
			Default(false),
		field.Bool("has_early_access"). // has_early_access is "false" by default
			Default(false),
		field.Bool("isKYBVerified").
			Default(false),
	}
}

// Edges of the User.
func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("sender_profile", SenderProfile.Type).
			Unique().
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("provider_profile", ProviderProfile.Type).
			Unique().
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("verification_token", VerificationToken.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("kyb_profile", KYBProfile.Type).
			Unique().
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

// Indexes of the User.
func (User) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("email", "scope").
			Unique(),
	}
}

// Hooks of the User.
func (User) Hooks() []ent.Hook {
	return []ent.Hook{
		hook.On(hashPasswordHook(), ent.OpUpdateOne|ent.OpUpdate|ent.OpCreate),
	}
}

// hashPasswordHook is a hook that hashes the password before saving the User entity.
func hashPasswordHook() ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return hook.UserFunc(func(ctx context.Context, m *gen.UserMutation) (ent.Value, error) {
			// Hash the password if it's set in the mutation.
			if password, ok := m.Field("password"); ok {
				hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password.(string)), 14)
				if err != nil {
					return nil, err
				}
				err = m.SetField("password", string(hashedPassword))
				if err != nil {
					return nil, err
				}
			}
			return next.Mutate(ctx, m)
		})
	}
}
