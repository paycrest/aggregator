// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/ent/apikey"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/senderprofile"
)

// APIKeyCreate is the builder for creating a APIKey entity.
type APIKeyCreate struct {
	config
	mutation *APIKeyMutation
	hooks    []Hook
	conflict []sql.ConflictOption
}

// SetSecret sets the "secret" field.
func (akc *APIKeyCreate) SetSecret(s string) *APIKeyCreate {
	akc.mutation.SetSecret(s)
	return akc
}

// SetID sets the "id" field.
func (akc *APIKeyCreate) SetID(u uuid.UUID) *APIKeyCreate {
	akc.mutation.SetID(u)
	return akc
}

// SetNillableID sets the "id" field if the given value is not nil.
func (akc *APIKeyCreate) SetNillableID(u *uuid.UUID) *APIKeyCreate {
	if u != nil {
		akc.SetID(*u)
	}
	return akc
}

// SetSenderProfileID sets the "sender_profile" edge to the SenderProfile entity by ID.
func (akc *APIKeyCreate) SetSenderProfileID(id uuid.UUID) *APIKeyCreate {
	akc.mutation.SetSenderProfileID(id)
	return akc
}

// SetNillableSenderProfileID sets the "sender_profile" edge to the SenderProfile entity by ID if the given value is not nil.
func (akc *APIKeyCreate) SetNillableSenderProfileID(id *uuid.UUID) *APIKeyCreate {
	if id != nil {
		akc = akc.SetSenderProfileID(*id)
	}
	return akc
}

// SetSenderProfile sets the "sender_profile" edge to the SenderProfile entity.
func (akc *APIKeyCreate) SetSenderProfile(s *SenderProfile) *APIKeyCreate {
	return akc.SetSenderProfileID(s.ID)
}

// SetProviderProfileID sets the "provider_profile" edge to the ProviderProfile entity by ID.
func (akc *APIKeyCreate) SetProviderProfileID(id string) *APIKeyCreate {
	akc.mutation.SetProviderProfileID(id)
	return akc
}

// SetNillableProviderProfileID sets the "provider_profile" edge to the ProviderProfile entity by ID if the given value is not nil.
func (akc *APIKeyCreate) SetNillableProviderProfileID(id *string) *APIKeyCreate {
	if id != nil {
		akc = akc.SetProviderProfileID(*id)
	}
	return akc
}

// SetProviderProfile sets the "provider_profile" edge to the ProviderProfile entity.
func (akc *APIKeyCreate) SetProviderProfile(p *ProviderProfile) *APIKeyCreate {
	return akc.SetProviderProfileID(p.ID)
}

// AddPaymentOrderIDs adds the "payment_orders" edge to the PaymentOrder entity by IDs.
func (akc *APIKeyCreate) AddPaymentOrderIDs(ids ...uuid.UUID) *APIKeyCreate {
	akc.mutation.AddPaymentOrderIDs(ids...)
	return akc
}

// AddPaymentOrders adds the "payment_orders" edges to the PaymentOrder entity.
func (akc *APIKeyCreate) AddPaymentOrders(p ...*PaymentOrder) *APIKeyCreate {
	ids := make([]uuid.UUID, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return akc.AddPaymentOrderIDs(ids...)
}

// Mutation returns the APIKeyMutation object of the builder.
func (akc *APIKeyCreate) Mutation() *APIKeyMutation {
	return akc.mutation
}

// Save creates the APIKey in the database.
func (akc *APIKeyCreate) Save(ctx context.Context) (*APIKey, error) {
	akc.defaults()
	return withHooks(ctx, akc.sqlSave, akc.mutation, akc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (akc *APIKeyCreate) SaveX(ctx context.Context) *APIKey {
	v, err := akc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (akc *APIKeyCreate) Exec(ctx context.Context) error {
	_, err := akc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (akc *APIKeyCreate) ExecX(ctx context.Context) {
	if err := akc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (akc *APIKeyCreate) defaults() {
	if _, ok := akc.mutation.ID(); !ok {
		v := apikey.DefaultID()
		akc.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (akc *APIKeyCreate) check() error {
	if _, ok := akc.mutation.Secret(); !ok {
		return &ValidationError{Name: "secret", err: errors.New(`ent: missing required field "APIKey.secret"`)}
	}
	if v, ok := akc.mutation.Secret(); ok {
		if err := apikey.SecretValidator(v); err != nil {
			return &ValidationError{Name: "secret", err: fmt.Errorf(`ent: validator failed for field "APIKey.secret": %w`, err)}
		}
	}
	return nil
}

func (akc *APIKeyCreate) sqlSave(ctx context.Context) (*APIKey, error) {
	if err := akc.check(); err != nil {
		return nil, err
	}
	_node, _spec := akc.createSpec()
	if err := sqlgraph.CreateNode(ctx, akc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(*uuid.UUID); ok {
			_node.ID = *id
		} else if err := _node.ID.Scan(_spec.ID.Value); err != nil {
			return nil, err
		}
	}
	akc.mutation.id = &_node.ID
	akc.mutation.done = true
	return _node, nil
}

func (akc *APIKeyCreate) createSpec() (*APIKey, *sqlgraph.CreateSpec) {
	var (
		_node = &APIKey{config: akc.config}
		_spec = sqlgraph.NewCreateSpec(apikey.Table, sqlgraph.NewFieldSpec(apikey.FieldID, field.TypeUUID))
	)
	_spec.OnConflict = akc.conflict
	if id, ok := akc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := akc.mutation.Secret(); ok {
		_spec.SetField(apikey.FieldSecret, field.TypeString, value)
		_node.Secret = value
	}
	if nodes := akc.mutation.SenderProfileIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   apikey.SenderProfileTable,
			Columns: []string{apikey.SenderProfileColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(senderprofile.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.sender_profile_api_key = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := akc.mutation.ProviderProfileIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   apikey.ProviderProfileTable,
			Columns: []string{apikey.ProviderProfileColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(providerprofile.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.provider_profile_api_key = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := akc.mutation.PaymentOrdersIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   apikey.PaymentOrdersTable,
			Columns: []string{apikey.PaymentOrdersColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(paymentorder.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.APIKey.Create().
//		SetSecret(v).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.APIKeyUpsert) {
//			SetSecret(v+v).
//		}).
//		Exec(ctx)
func (akc *APIKeyCreate) OnConflict(opts ...sql.ConflictOption) *APIKeyUpsertOne {
	akc.conflict = opts
	return &APIKeyUpsertOne{
		create: akc,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.APIKey.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (akc *APIKeyCreate) OnConflictColumns(columns ...string) *APIKeyUpsertOne {
	akc.conflict = append(akc.conflict, sql.ConflictColumns(columns...))
	return &APIKeyUpsertOne{
		create: akc,
	}
}

type (
	// APIKeyUpsertOne is the builder for "upsert"-ing
	//  one APIKey node.
	APIKeyUpsertOne struct {
		create *APIKeyCreate
	}

	// APIKeyUpsert is the "OnConflict" setter.
	APIKeyUpsert struct {
		*sql.UpdateSet
	}
)

// SetSecret sets the "secret" field.
func (u *APIKeyUpsert) SetSecret(v string) *APIKeyUpsert {
	u.Set(apikey.FieldSecret, v)
	return u
}

// UpdateSecret sets the "secret" field to the value that was provided on create.
func (u *APIKeyUpsert) UpdateSecret() *APIKeyUpsert {
	u.SetExcluded(apikey.FieldSecret)
	return u
}

// UpdateNewValues updates the mutable fields using the new values that were set on create except the ID field.
// Using this option is equivalent to using:
//
//	client.APIKey.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(apikey.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *APIKeyUpsertOne) UpdateNewValues() *APIKeyUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		if _, exists := u.create.mutation.ID(); exists {
			s.SetIgnore(apikey.FieldID)
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.APIKey.Create().
//	    OnConflict(sql.ResolveWithIgnore()).
//	    Exec(ctx)
func (u *APIKeyUpsertOne) Ignore() *APIKeyUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *APIKeyUpsertOne) DoNothing() *APIKeyUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the APIKeyCreate.OnConflict
// documentation for more info.
func (u *APIKeyUpsertOne) Update(set func(*APIKeyUpsert)) *APIKeyUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&APIKeyUpsert{UpdateSet: update})
	}))
	return u
}

// SetSecret sets the "secret" field.
func (u *APIKeyUpsertOne) SetSecret(v string) *APIKeyUpsertOne {
	return u.Update(func(s *APIKeyUpsert) {
		s.SetSecret(v)
	})
}

// UpdateSecret sets the "secret" field to the value that was provided on create.
func (u *APIKeyUpsertOne) UpdateSecret() *APIKeyUpsertOne {
	return u.Update(func(s *APIKeyUpsert) {
		s.UpdateSecret()
	})
}

// Exec executes the query.
func (u *APIKeyUpsertOne) Exec(ctx context.Context) error {
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for APIKeyCreate.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *APIKeyUpsertOne) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}

// Exec executes the UPSERT query and returns the inserted/updated ID.
func (u *APIKeyUpsertOne) ID(ctx context.Context) (id uuid.UUID, err error) {
	if u.create.driver.Dialect() == dialect.MySQL {
		// In case of "ON CONFLICT", there is no way to get back non-numeric ID
		// fields from the database since MySQL does not support the RETURNING clause.
		return id, errors.New("ent: APIKeyUpsertOne.ID is not supported by MySQL driver. Use APIKeyUpsertOne.Exec instead")
	}
	node, err := u.create.Save(ctx)
	if err != nil {
		return id, err
	}
	return node.ID, nil
}

// IDX is like ID, but panics if an error occurs.
func (u *APIKeyUpsertOne) IDX(ctx context.Context) uuid.UUID {
	id, err := u.ID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// APIKeyCreateBulk is the builder for creating many APIKey entities in bulk.
type APIKeyCreateBulk struct {
	config
	err      error
	builders []*APIKeyCreate
	conflict []sql.ConflictOption
}

// Save creates the APIKey entities in the database.
func (akcb *APIKeyCreateBulk) Save(ctx context.Context) ([]*APIKey, error) {
	if akcb.err != nil {
		return nil, akcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(akcb.builders))
	nodes := make([]*APIKey, len(akcb.builders))
	mutators := make([]Mutator, len(akcb.builders))
	for i := range akcb.builders {
		func(i int, root context.Context) {
			builder := akcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*APIKeyMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, akcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					spec.OnConflict = akcb.conflict
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, akcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, akcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (akcb *APIKeyCreateBulk) SaveX(ctx context.Context) []*APIKey {
	v, err := akcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (akcb *APIKeyCreateBulk) Exec(ctx context.Context) error {
	_, err := akcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (akcb *APIKeyCreateBulk) ExecX(ctx context.Context) {
	if err := akcb.Exec(ctx); err != nil {
		panic(err)
	}
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.APIKey.CreateBulk(builders...).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.APIKeyUpsert) {
//			SetSecret(v+v).
//		}).
//		Exec(ctx)
func (akcb *APIKeyCreateBulk) OnConflict(opts ...sql.ConflictOption) *APIKeyUpsertBulk {
	akcb.conflict = opts
	return &APIKeyUpsertBulk{
		create: akcb,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.APIKey.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (akcb *APIKeyCreateBulk) OnConflictColumns(columns ...string) *APIKeyUpsertBulk {
	akcb.conflict = append(akcb.conflict, sql.ConflictColumns(columns...))
	return &APIKeyUpsertBulk{
		create: akcb,
	}
}

// APIKeyUpsertBulk is the builder for "upsert"-ing
// a bulk of APIKey nodes.
type APIKeyUpsertBulk struct {
	create *APIKeyCreateBulk
}

// UpdateNewValues updates the mutable fields using the new values that
// were set on create. Using this option is equivalent to using:
//
//	client.APIKey.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(apikey.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *APIKeyUpsertBulk) UpdateNewValues() *APIKeyUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		for _, b := range u.create.builders {
			if _, exists := b.mutation.ID(); exists {
				s.SetIgnore(apikey.FieldID)
			}
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.APIKey.Create().
//		OnConflict(sql.ResolveWithIgnore()).
//		Exec(ctx)
func (u *APIKeyUpsertBulk) Ignore() *APIKeyUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *APIKeyUpsertBulk) DoNothing() *APIKeyUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the APIKeyCreateBulk.OnConflict
// documentation for more info.
func (u *APIKeyUpsertBulk) Update(set func(*APIKeyUpsert)) *APIKeyUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&APIKeyUpsert{UpdateSet: update})
	}))
	return u
}

// SetSecret sets the "secret" field.
func (u *APIKeyUpsertBulk) SetSecret(v string) *APIKeyUpsertBulk {
	return u.Update(func(s *APIKeyUpsert) {
		s.SetSecret(v)
	})
}

// UpdateSecret sets the "secret" field to the value that was provided on create.
func (u *APIKeyUpsertBulk) UpdateSecret() *APIKeyUpsertBulk {
	return u.Update(func(s *APIKeyUpsert) {
		s.UpdateSecret()
	})
}

// Exec executes the query.
func (u *APIKeyUpsertBulk) Exec(ctx context.Context) error {
	if u.create.err != nil {
		return u.create.err
	}
	for i, b := range u.create.builders {
		if len(b.conflict) != 0 {
			return fmt.Errorf("ent: OnConflict was set for builder %d. Set it on the APIKeyCreateBulk instead", i)
		}
	}
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for APIKeyCreateBulk.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *APIKeyUpsertBulk) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}
