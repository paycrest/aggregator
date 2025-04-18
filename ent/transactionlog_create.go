// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/ent/transactionlog"
)

// TransactionLogCreate is the builder for creating a TransactionLog entity.
type TransactionLogCreate struct {
	config
	mutation *TransactionLogMutation
	hooks    []Hook
	conflict []sql.ConflictOption
}

// SetGatewayID sets the "gateway_id" field.
func (tlc *TransactionLogCreate) SetGatewayID(s string) *TransactionLogCreate {
	tlc.mutation.SetGatewayID(s)
	return tlc
}

// SetNillableGatewayID sets the "gateway_id" field if the given value is not nil.
func (tlc *TransactionLogCreate) SetNillableGatewayID(s *string) *TransactionLogCreate {
	if s != nil {
		tlc.SetGatewayID(*s)
	}
	return tlc
}

// SetStatus sets the "status" field.
func (tlc *TransactionLogCreate) SetStatus(t transactionlog.Status) *TransactionLogCreate {
	tlc.mutation.SetStatus(t)
	return tlc
}

// SetNillableStatus sets the "status" field if the given value is not nil.
func (tlc *TransactionLogCreate) SetNillableStatus(t *transactionlog.Status) *TransactionLogCreate {
	if t != nil {
		tlc.SetStatus(*t)
	}
	return tlc
}

// SetNetwork sets the "network" field.
func (tlc *TransactionLogCreate) SetNetwork(s string) *TransactionLogCreate {
	tlc.mutation.SetNetwork(s)
	return tlc
}

// SetNillableNetwork sets the "network" field if the given value is not nil.
func (tlc *TransactionLogCreate) SetNillableNetwork(s *string) *TransactionLogCreate {
	if s != nil {
		tlc.SetNetwork(*s)
	}
	return tlc
}

// SetTxHash sets the "tx_hash" field.
func (tlc *TransactionLogCreate) SetTxHash(s string) *TransactionLogCreate {
	tlc.mutation.SetTxHash(s)
	return tlc
}

// SetNillableTxHash sets the "tx_hash" field if the given value is not nil.
func (tlc *TransactionLogCreate) SetNillableTxHash(s *string) *TransactionLogCreate {
	if s != nil {
		tlc.SetTxHash(*s)
	}
	return tlc
}

// SetMetadata sets the "metadata" field.
func (tlc *TransactionLogCreate) SetMetadata(m map[string]interface{}) *TransactionLogCreate {
	tlc.mutation.SetMetadata(m)
	return tlc
}

// SetCreatedAt sets the "created_at" field.
func (tlc *TransactionLogCreate) SetCreatedAt(t time.Time) *TransactionLogCreate {
	tlc.mutation.SetCreatedAt(t)
	return tlc
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (tlc *TransactionLogCreate) SetNillableCreatedAt(t *time.Time) *TransactionLogCreate {
	if t != nil {
		tlc.SetCreatedAt(*t)
	}
	return tlc
}

// SetID sets the "id" field.
func (tlc *TransactionLogCreate) SetID(u uuid.UUID) *TransactionLogCreate {
	tlc.mutation.SetID(u)
	return tlc
}

// SetNillableID sets the "id" field if the given value is not nil.
func (tlc *TransactionLogCreate) SetNillableID(u *uuid.UUID) *TransactionLogCreate {
	if u != nil {
		tlc.SetID(*u)
	}
	return tlc
}

// Mutation returns the TransactionLogMutation object of the builder.
func (tlc *TransactionLogCreate) Mutation() *TransactionLogMutation {
	return tlc.mutation
}

// Save creates the TransactionLog in the database.
func (tlc *TransactionLogCreate) Save(ctx context.Context) (*TransactionLog, error) {
	tlc.defaults()
	return withHooks(ctx, tlc.sqlSave, tlc.mutation, tlc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (tlc *TransactionLogCreate) SaveX(ctx context.Context) *TransactionLog {
	v, err := tlc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (tlc *TransactionLogCreate) Exec(ctx context.Context) error {
	_, err := tlc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (tlc *TransactionLogCreate) ExecX(ctx context.Context) {
	if err := tlc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (tlc *TransactionLogCreate) defaults() {
	if _, ok := tlc.mutation.Status(); !ok {
		v := transactionlog.DefaultStatus
		tlc.mutation.SetStatus(v)
	}
	if _, ok := tlc.mutation.CreatedAt(); !ok {
		v := transactionlog.DefaultCreatedAt()
		tlc.mutation.SetCreatedAt(v)
	}
	if _, ok := tlc.mutation.ID(); !ok {
		v := transactionlog.DefaultID()
		tlc.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (tlc *TransactionLogCreate) check() error {
	if _, ok := tlc.mutation.Status(); !ok {
		return &ValidationError{Name: "status", err: errors.New(`ent: missing required field "TransactionLog.status"`)}
	}
	if v, ok := tlc.mutation.Status(); ok {
		if err := transactionlog.StatusValidator(v); err != nil {
			return &ValidationError{Name: "status", err: fmt.Errorf(`ent: validator failed for field "TransactionLog.status": %w`, err)}
		}
	}
	if _, ok := tlc.mutation.Metadata(); !ok {
		return &ValidationError{Name: "metadata", err: errors.New(`ent: missing required field "TransactionLog.metadata"`)}
	}
	if _, ok := tlc.mutation.CreatedAt(); !ok {
		return &ValidationError{Name: "created_at", err: errors.New(`ent: missing required field "TransactionLog.created_at"`)}
	}
	return nil
}

func (tlc *TransactionLogCreate) sqlSave(ctx context.Context) (*TransactionLog, error) {
	if err := tlc.check(); err != nil {
		return nil, err
	}
	_node, _spec := tlc.createSpec()
	if err := sqlgraph.CreateNode(ctx, tlc.driver, _spec); err != nil {
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
	tlc.mutation.id = &_node.ID
	tlc.mutation.done = true
	return _node, nil
}

func (tlc *TransactionLogCreate) createSpec() (*TransactionLog, *sqlgraph.CreateSpec) {
	var (
		_node = &TransactionLog{config: tlc.config}
		_spec = sqlgraph.NewCreateSpec(transactionlog.Table, sqlgraph.NewFieldSpec(transactionlog.FieldID, field.TypeUUID))
	)
	_spec.OnConflict = tlc.conflict
	if id, ok := tlc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := tlc.mutation.GatewayID(); ok {
		_spec.SetField(transactionlog.FieldGatewayID, field.TypeString, value)
		_node.GatewayID = value
	}
	if value, ok := tlc.mutation.Status(); ok {
		_spec.SetField(transactionlog.FieldStatus, field.TypeEnum, value)
		_node.Status = value
	}
	if value, ok := tlc.mutation.Network(); ok {
		_spec.SetField(transactionlog.FieldNetwork, field.TypeString, value)
		_node.Network = value
	}
	if value, ok := tlc.mutation.TxHash(); ok {
		_spec.SetField(transactionlog.FieldTxHash, field.TypeString, value)
		_node.TxHash = value
	}
	if value, ok := tlc.mutation.Metadata(); ok {
		_spec.SetField(transactionlog.FieldMetadata, field.TypeJSON, value)
		_node.Metadata = value
	}
	if value, ok := tlc.mutation.CreatedAt(); ok {
		_spec.SetField(transactionlog.FieldCreatedAt, field.TypeTime, value)
		_node.CreatedAt = value
	}
	return _node, _spec
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.TransactionLog.Create().
//		SetGatewayID(v).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.TransactionLogUpsert) {
//			SetGatewayID(v+v).
//		}).
//		Exec(ctx)
func (tlc *TransactionLogCreate) OnConflict(opts ...sql.ConflictOption) *TransactionLogUpsertOne {
	tlc.conflict = opts
	return &TransactionLogUpsertOne{
		create: tlc,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.TransactionLog.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (tlc *TransactionLogCreate) OnConflictColumns(columns ...string) *TransactionLogUpsertOne {
	tlc.conflict = append(tlc.conflict, sql.ConflictColumns(columns...))
	return &TransactionLogUpsertOne{
		create: tlc,
	}
}

type (
	// TransactionLogUpsertOne is the builder for "upsert"-ing
	//  one TransactionLog node.
	TransactionLogUpsertOne struct {
		create *TransactionLogCreate
	}

	// TransactionLogUpsert is the "OnConflict" setter.
	TransactionLogUpsert struct {
		*sql.UpdateSet
	}
)

// SetGatewayID sets the "gateway_id" field.
func (u *TransactionLogUpsert) SetGatewayID(v string) *TransactionLogUpsert {
	u.Set(transactionlog.FieldGatewayID, v)
	return u
}

// UpdateGatewayID sets the "gateway_id" field to the value that was provided on create.
func (u *TransactionLogUpsert) UpdateGatewayID() *TransactionLogUpsert {
	u.SetExcluded(transactionlog.FieldGatewayID)
	return u
}

// ClearGatewayID clears the value of the "gateway_id" field.
func (u *TransactionLogUpsert) ClearGatewayID() *TransactionLogUpsert {
	u.SetNull(transactionlog.FieldGatewayID)
	return u
}

// SetNetwork sets the "network" field.
func (u *TransactionLogUpsert) SetNetwork(v string) *TransactionLogUpsert {
	u.Set(transactionlog.FieldNetwork, v)
	return u
}

// UpdateNetwork sets the "network" field to the value that was provided on create.
func (u *TransactionLogUpsert) UpdateNetwork() *TransactionLogUpsert {
	u.SetExcluded(transactionlog.FieldNetwork)
	return u
}

// ClearNetwork clears the value of the "network" field.
func (u *TransactionLogUpsert) ClearNetwork() *TransactionLogUpsert {
	u.SetNull(transactionlog.FieldNetwork)
	return u
}

// SetTxHash sets the "tx_hash" field.
func (u *TransactionLogUpsert) SetTxHash(v string) *TransactionLogUpsert {
	u.Set(transactionlog.FieldTxHash, v)
	return u
}

// UpdateTxHash sets the "tx_hash" field to the value that was provided on create.
func (u *TransactionLogUpsert) UpdateTxHash() *TransactionLogUpsert {
	u.SetExcluded(transactionlog.FieldTxHash)
	return u
}

// ClearTxHash clears the value of the "tx_hash" field.
func (u *TransactionLogUpsert) ClearTxHash() *TransactionLogUpsert {
	u.SetNull(transactionlog.FieldTxHash)
	return u
}

// SetMetadata sets the "metadata" field.
func (u *TransactionLogUpsert) SetMetadata(v map[string]interface{}) *TransactionLogUpsert {
	u.Set(transactionlog.FieldMetadata, v)
	return u
}

// UpdateMetadata sets the "metadata" field to the value that was provided on create.
func (u *TransactionLogUpsert) UpdateMetadata() *TransactionLogUpsert {
	u.SetExcluded(transactionlog.FieldMetadata)
	return u
}

// UpdateNewValues updates the mutable fields using the new values that were set on create except the ID field.
// Using this option is equivalent to using:
//
//	client.TransactionLog.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(transactionlog.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *TransactionLogUpsertOne) UpdateNewValues() *TransactionLogUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		if _, exists := u.create.mutation.ID(); exists {
			s.SetIgnore(transactionlog.FieldID)
		}
		if _, exists := u.create.mutation.Status(); exists {
			s.SetIgnore(transactionlog.FieldStatus)
		}
		if _, exists := u.create.mutation.CreatedAt(); exists {
			s.SetIgnore(transactionlog.FieldCreatedAt)
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.TransactionLog.Create().
//	    OnConflict(sql.ResolveWithIgnore()).
//	    Exec(ctx)
func (u *TransactionLogUpsertOne) Ignore() *TransactionLogUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *TransactionLogUpsertOne) DoNothing() *TransactionLogUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the TransactionLogCreate.OnConflict
// documentation for more info.
func (u *TransactionLogUpsertOne) Update(set func(*TransactionLogUpsert)) *TransactionLogUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&TransactionLogUpsert{UpdateSet: update})
	}))
	return u
}

// SetGatewayID sets the "gateway_id" field.
func (u *TransactionLogUpsertOne) SetGatewayID(v string) *TransactionLogUpsertOne {
	return u.Update(func(s *TransactionLogUpsert) {
		s.SetGatewayID(v)
	})
}

// UpdateGatewayID sets the "gateway_id" field to the value that was provided on create.
func (u *TransactionLogUpsertOne) UpdateGatewayID() *TransactionLogUpsertOne {
	return u.Update(func(s *TransactionLogUpsert) {
		s.UpdateGatewayID()
	})
}

// ClearGatewayID clears the value of the "gateway_id" field.
func (u *TransactionLogUpsertOne) ClearGatewayID() *TransactionLogUpsertOne {
	return u.Update(func(s *TransactionLogUpsert) {
		s.ClearGatewayID()
	})
}

// SetNetwork sets the "network" field.
func (u *TransactionLogUpsertOne) SetNetwork(v string) *TransactionLogUpsertOne {
	return u.Update(func(s *TransactionLogUpsert) {
		s.SetNetwork(v)
	})
}

// UpdateNetwork sets the "network" field to the value that was provided on create.
func (u *TransactionLogUpsertOne) UpdateNetwork() *TransactionLogUpsertOne {
	return u.Update(func(s *TransactionLogUpsert) {
		s.UpdateNetwork()
	})
}

// ClearNetwork clears the value of the "network" field.
func (u *TransactionLogUpsertOne) ClearNetwork() *TransactionLogUpsertOne {
	return u.Update(func(s *TransactionLogUpsert) {
		s.ClearNetwork()
	})
}

// SetTxHash sets the "tx_hash" field.
func (u *TransactionLogUpsertOne) SetTxHash(v string) *TransactionLogUpsertOne {
	return u.Update(func(s *TransactionLogUpsert) {
		s.SetTxHash(v)
	})
}

// UpdateTxHash sets the "tx_hash" field to the value that was provided on create.
func (u *TransactionLogUpsertOne) UpdateTxHash() *TransactionLogUpsertOne {
	return u.Update(func(s *TransactionLogUpsert) {
		s.UpdateTxHash()
	})
}

// ClearTxHash clears the value of the "tx_hash" field.
func (u *TransactionLogUpsertOne) ClearTxHash() *TransactionLogUpsertOne {
	return u.Update(func(s *TransactionLogUpsert) {
		s.ClearTxHash()
	})
}

// SetMetadata sets the "metadata" field.
func (u *TransactionLogUpsertOne) SetMetadata(v map[string]interface{}) *TransactionLogUpsertOne {
	return u.Update(func(s *TransactionLogUpsert) {
		s.SetMetadata(v)
	})
}

// UpdateMetadata sets the "metadata" field to the value that was provided on create.
func (u *TransactionLogUpsertOne) UpdateMetadata() *TransactionLogUpsertOne {
	return u.Update(func(s *TransactionLogUpsert) {
		s.UpdateMetadata()
	})
}

// Exec executes the query.
func (u *TransactionLogUpsertOne) Exec(ctx context.Context) error {
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for TransactionLogCreate.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *TransactionLogUpsertOne) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}

// Exec executes the UPSERT query and returns the inserted/updated ID.
func (u *TransactionLogUpsertOne) ID(ctx context.Context) (id uuid.UUID, err error) {
	if u.create.driver.Dialect() == dialect.MySQL {
		// In case of "ON CONFLICT", there is no way to get back non-numeric ID
		// fields from the database since MySQL does not support the RETURNING clause.
		return id, errors.New("ent: TransactionLogUpsertOne.ID is not supported by MySQL driver. Use TransactionLogUpsertOne.Exec instead")
	}
	node, err := u.create.Save(ctx)
	if err != nil {
		return id, err
	}
	return node.ID, nil
}

// IDX is like ID, but panics if an error occurs.
func (u *TransactionLogUpsertOne) IDX(ctx context.Context) uuid.UUID {
	id, err := u.ID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// TransactionLogCreateBulk is the builder for creating many TransactionLog entities in bulk.
type TransactionLogCreateBulk struct {
	config
	err      error
	builders []*TransactionLogCreate
	conflict []sql.ConflictOption
}

// Save creates the TransactionLog entities in the database.
func (tlcb *TransactionLogCreateBulk) Save(ctx context.Context) ([]*TransactionLog, error) {
	if tlcb.err != nil {
		return nil, tlcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(tlcb.builders))
	nodes := make([]*TransactionLog, len(tlcb.builders))
	mutators := make([]Mutator, len(tlcb.builders))
	for i := range tlcb.builders {
		func(i int, root context.Context) {
			builder := tlcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*TransactionLogMutation)
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
					_, err = mutators[i+1].Mutate(root, tlcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					spec.OnConflict = tlcb.conflict
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, tlcb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, tlcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (tlcb *TransactionLogCreateBulk) SaveX(ctx context.Context) []*TransactionLog {
	v, err := tlcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (tlcb *TransactionLogCreateBulk) Exec(ctx context.Context) error {
	_, err := tlcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (tlcb *TransactionLogCreateBulk) ExecX(ctx context.Context) {
	if err := tlcb.Exec(ctx); err != nil {
		panic(err)
	}
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.TransactionLog.CreateBulk(builders...).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.TransactionLogUpsert) {
//			SetGatewayID(v+v).
//		}).
//		Exec(ctx)
func (tlcb *TransactionLogCreateBulk) OnConflict(opts ...sql.ConflictOption) *TransactionLogUpsertBulk {
	tlcb.conflict = opts
	return &TransactionLogUpsertBulk{
		create: tlcb,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.TransactionLog.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (tlcb *TransactionLogCreateBulk) OnConflictColumns(columns ...string) *TransactionLogUpsertBulk {
	tlcb.conflict = append(tlcb.conflict, sql.ConflictColumns(columns...))
	return &TransactionLogUpsertBulk{
		create: tlcb,
	}
}

// TransactionLogUpsertBulk is the builder for "upsert"-ing
// a bulk of TransactionLog nodes.
type TransactionLogUpsertBulk struct {
	create *TransactionLogCreateBulk
}

// UpdateNewValues updates the mutable fields using the new values that
// were set on create. Using this option is equivalent to using:
//
//	client.TransactionLog.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(transactionlog.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *TransactionLogUpsertBulk) UpdateNewValues() *TransactionLogUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		for _, b := range u.create.builders {
			if _, exists := b.mutation.ID(); exists {
				s.SetIgnore(transactionlog.FieldID)
			}
			if _, exists := b.mutation.Status(); exists {
				s.SetIgnore(transactionlog.FieldStatus)
			}
			if _, exists := b.mutation.CreatedAt(); exists {
				s.SetIgnore(transactionlog.FieldCreatedAt)
			}
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.TransactionLog.Create().
//		OnConflict(sql.ResolveWithIgnore()).
//		Exec(ctx)
func (u *TransactionLogUpsertBulk) Ignore() *TransactionLogUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *TransactionLogUpsertBulk) DoNothing() *TransactionLogUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the TransactionLogCreateBulk.OnConflict
// documentation for more info.
func (u *TransactionLogUpsertBulk) Update(set func(*TransactionLogUpsert)) *TransactionLogUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&TransactionLogUpsert{UpdateSet: update})
	}))
	return u
}

// SetGatewayID sets the "gateway_id" field.
func (u *TransactionLogUpsertBulk) SetGatewayID(v string) *TransactionLogUpsertBulk {
	return u.Update(func(s *TransactionLogUpsert) {
		s.SetGatewayID(v)
	})
}

// UpdateGatewayID sets the "gateway_id" field to the value that was provided on create.
func (u *TransactionLogUpsertBulk) UpdateGatewayID() *TransactionLogUpsertBulk {
	return u.Update(func(s *TransactionLogUpsert) {
		s.UpdateGatewayID()
	})
}

// ClearGatewayID clears the value of the "gateway_id" field.
func (u *TransactionLogUpsertBulk) ClearGatewayID() *TransactionLogUpsertBulk {
	return u.Update(func(s *TransactionLogUpsert) {
		s.ClearGatewayID()
	})
}

// SetNetwork sets the "network" field.
func (u *TransactionLogUpsertBulk) SetNetwork(v string) *TransactionLogUpsertBulk {
	return u.Update(func(s *TransactionLogUpsert) {
		s.SetNetwork(v)
	})
}

// UpdateNetwork sets the "network" field to the value that was provided on create.
func (u *TransactionLogUpsertBulk) UpdateNetwork() *TransactionLogUpsertBulk {
	return u.Update(func(s *TransactionLogUpsert) {
		s.UpdateNetwork()
	})
}

// ClearNetwork clears the value of the "network" field.
func (u *TransactionLogUpsertBulk) ClearNetwork() *TransactionLogUpsertBulk {
	return u.Update(func(s *TransactionLogUpsert) {
		s.ClearNetwork()
	})
}

// SetTxHash sets the "tx_hash" field.
func (u *TransactionLogUpsertBulk) SetTxHash(v string) *TransactionLogUpsertBulk {
	return u.Update(func(s *TransactionLogUpsert) {
		s.SetTxHash(v)
	})
}

// UpdateTxHash sets the "tx_hash" field to the value that was provided on create.
func (u *TransactionLogUpsertBulk) UpdateTxHash() *TransactionLogUpsertBulk {
	return u.Update(func(s *TransactionLogUpsert) {
		s.UpdateTxHash()
	})
}

// ClearTxHash clears the value of the "tx_hash" field.
func (u *TransactionLogUpsertBulk) ClearTxHash() *TransactionLogUpsertBulk {
	return u.Update(func(s *TransactionLogUpsert) {
		s.ClearTxHash()
	})
}

// SetMetadata sets the "metadata" field.
func (u *TransactionLogUpsertBulk) SetMetadata(v map[string]interface{}) *TransactionLogUpsertBulk {
	return u.Update(func(s *TransactionLogUpsert) {
		s.SetMetadata(v)
	})
}

// UpdateMetadata sets the "metadata" field to the value that was provided on create.
func (u *TransactionLogUpsertBulk) UpdateMetadata() *TransactionLogUpsertBulk {
	return u.Update(func(s *TransactionLogUpsert) {
		s.UpdateMetadata()
	})
}

// Exec executes the query.
func (u *TransactionLogUpsertBulk) Exec(ctx context.Context) error {
	if u.create.err != nil {
		return u.create.err
	}
	for i, b := range u.create.builders {
		if len(b.conflict) != 0 {
			return fmt.Errorf("ent: OnConflict was set for builder %d. Set it on the TransactionLogCreateBulk instead", i)
		}
	}
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for TransactionLogCreateBulk.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *TransactionLogUpsertBulk) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}
