package schema

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	gen "github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/hook"
	"golang.org/x/crypto/bcrypt"
)

// VerificationToken holds the schema definition for the VerificationToken entity.
type VerificationToken struct {
	ent.Schema
}

// Mixin of the VerificationToken.
func (VerificationToken) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the VerificationToken.
func (VerificationToken) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New),
		field.String("token").Immutable(),
		field.Enum("scope").Values("emailVerification", "resetPassword"),
		field.Time("expiry_at").Immutable().Default(time.Now().Add(time.Hour * 9000)),
	}
}

// Edges of the VerificationToken.
func (VerificationToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).
			Ref("verification_token").
			Unique().
			Required().
			Immutable(),
	}
}

// Hooks of the VerificationToken.
func (VerificationToken) Hooks() []ent.Hook {
	return []ent.Hook{
		hook.On(generateVerificationToken(), ent.OpCreate),
	}
}

// generateVerificationToken is a hook that generates a bcrypt token based on the provided email string, before saving the VerificationToken entity.
func generateVerificationToken() ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return hook.VerificationTokenFunc(func(ctx context.Context, m *gen.VerificationTokenMutation) (ent.Value, error) {
			if id, exist := m.OwnerID(); exist {
				user, err := m.Client().User.Get(ctx, id)
				if err != nil {
					return nil, err
				}

				hash, _ := bcrypt.GenerateFromPassword([]byte(user.Email), bcrypt.DefaultCost)
				hasher := md5.New()
				hasher.Write(hash)

				if err = m.SetField("token", hex.EncodeToString(hasher.Sum(nil))); err != nil {
					return nil, err
				}
			}
			return next.Mutate(ctx, m)
		})
	}
}
