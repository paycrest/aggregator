package schema

import (
	"context"
	"fmt"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

// TimeMixin adds created_at and updated_at timestamps.
type TimeMixin struct {
	mixin.Schema
}

// Fields of the TimeMixin.
func (TimeMixin) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Immutable().
			Default(time.Now),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// SoftDeleteMixin implements soft delete by setting `deleted_at` instead of deleting.
type SoftDeleteMixin struct {
	mixin.Schema
}

// Fields for SoftDeleteMixin.
func (SoftDeleteMixin) Fields() []ent.Field {
	return []ent.Field{
		field.Time("deleted_at").
			Optional().
			Nillable(), // Allows NULL values
	}
}

type softDeleteKey struct{}

// SkipSoftDelete allows bypassing the soft delete filter.
func SkipSoftDelete(ctx context.Context) context.Context {
	return context.WithValue(ctx, softDeleteKey{}, true)
}

// Interceptors of the SoftDeleteMixin.
func (d SoftDeleteMixin) Interceptors() []ent.Interceptor {
	return []ent.Interceptor{
		ent.InterceptFunc(func(next ent.Querier) ent.Querier {
			return ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
				// Skip soft-delete, meaning include soft-deleted entities
				if skip, _ := ctx.Value(softDeleteKey{}).(bool); skip {
					return next.Query(ctx, q)
				}

				// Add the predicate to filter out soft-deleted entities
				if whereP, ok := q.(interface{ WhereP(...func(*sql.Selector)) }); ok {
					whereP.WhereP(sql.FieldIsNull("deleted_at"))
				}

				return next.Query(ctx, q)
			})
		}),
	}
}

// Hooks of the SoftDeleteMixin.
func (d SoftDeleteMixin) Hooks() []ent.Hook {
	return []ent.Hook{
		ent.Hook(func(next ent.Mutator) ent.Mutator {
			return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
				// Skip soft-delete, meaning delete permanently.
				if skip, _ := ctx.Value(softDeleteKey{}).(bool); skip {
					return next.Mutate(ctx, m)
				}

				// Convert delete to soft delete by setting `deleted_at`
				if m.Op().Is(ent.OpDelete | ent.OpDeleteOne) {
					// Ensure the mutation supports setting fields
					if mut, ok := m.(interface {
						SetField(string, interface{}) error
					}); ok {
						_ = mut.SetField("deleted_at", time.Now())

						// Change operation from delete to update (ent does not have SetOp)
						mutOp, ok := m.(interface {
							Op() ent.Op
							SetOp(ent.Op)
						})
						if ok {
							mutOp.SetOp(ent.OpUpdate)
						}
					} else {
						return nil, fmt.Errorf("mutation does not support SetField: %T", m)
					}

					return next.Mutate(ctx, m)
				}

				return next.Mutate(ctx, m)
			})
		}),
	}
}
