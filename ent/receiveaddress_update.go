// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/predicate"
	"github.com/paycrest/aggregator/ent/receiveaddress"
)

// ReceiveAddressUpdate is the builder for updating ReceiveAddress entities.
type ReceiveAddressUpdate struct {
	config
	hooks    []Hook
	mutation *ReceiveAddressMutation
}

// Where appends a list predicates to the ReceiveAddressUpdate builder.
func (rau *ReceiveAddressUpdate) Where(ps ...predicate.ReceiveAddress) *ReceiveAddressUpdate {
	rau.mutation.Where(ps...)
	return rau
}

// SetUpdatedAt sets the "updated_at" field.
func (rau *ReceiveAddressUpdate) SetUpdatedAt(t time.Time) *ReceiveAddressUpdate {
	rau.mutation.SetUpdatedAt(t)
	return rau
}

// SetAddress sets the "address" field.
func (rau *ReceiveAddressUpdate) SetAddress(s string) *ReceiveAddressUpdate {
	rau.mutation.SetAddress(s)
	return rau
}

// SetNillableAddress sets the "address" field if the given value is not nil.
func (rau *ReceiveAddressUpdate) SetNillableAddress(s *string) *ReceiveAddressUpdate {
	if s != nil {
		rau.SetAddress(*s)
	}
	return rau
}

// SetSalt sets the "salt" field.
func (rau *ReceiveAddressUpdate) SetSalt(b []byte) *ReceiveAddressUpdate {
	rau.mutation.SetSalt(b)
	return rau
}

// ClearSalt clears the value of the "salt" field.
func (rau *ReceiveAddressUpdate) ClearSalt() *ReceiveAddressUpdate {
	rau.mutation.ClearSalt()
	return rau
}

// SetStatus sets the "status" field.
func (rau *ReceiveAddressUpdate) SetStatus(r receiveaddress.Status) *ReceiveAddressUpdate {
	rau.mutation.SetStatus(r)
	return rau
}

// SetNillableStatus sets the "status" field if the given value is not nil.
func (rau *ReceiveAddressUpdate) SetNillableStatus(r *receiveaddress.Status) *ReceiveAddressUpdate {
	if r != nil {
		rau.SetStatus(*r)
	}
	return rau
}

// SetLastIndexedBlock sets the "last_indexed_block" field.
func (rau *ReceiveAddressUpdate) SetLastIndexedBlock(i int64) *ReceiveAddressUpdate {
	rau.mutation.ResetLastIndexedBlock()
	rau.mutation.SetLastIndexedBlock(i)
	return rau
}

// SetNillableLastIndexedBlock sets the "last_indexed_block" field if the given value is not nil.
func (rau *ReceiveAddressUpdate) SetNillableLastIndexedBlock(i *int64) *ReceiveAddressUpdate {
	if i != nil {
		rau.SetLastIndexedBlock(*i)
	}
	return rau
}

// AddLastIndexedBlock adds i to the "last_indexed_block" field.
func (rau *ReceiveAddressUpdate) AddLastIndexedBlock(i int64) *ReceiveAddressUpdate {
	rau.mutation.AddLastIndexedBlock(i)
	return rau
}

// ClearLastIndexedBlock clears the value of the "last_indexed_block" field.
func (rau *ReceiveAddressUpdate) ClearLastIndexedBlock() *ReceiveAddressUpdate {
	rau.mutation.ClearLastIndexedBlock()
	return rau
}

// SetLastUsed sets the "last_used" field.
func (rau *ReceiveAddressUpdate) SetLastUsed(t time.Time) *ReceiveAddressUpdate {
	rau.mutation.SetLastUsed(t)
	return rau
}

// SetNillableLastUsed sets the "last_used" field if the given value is not nil.
func (rau *ReceiveAddressUpdate) SetNillableLastUsed(t *time.Time) *ReceiveAddressUpdate {
	if t != nil {
		rau.SetLastUsed(*t)
	}
	return rau
}

// ClearLastUsed clears the value of the "last_used" field.
func (rau *ReceiveAddressUpdate) ClearLastUsed() *ReceiveAddressUpdate {
	rau.mutation.ClearLastUsed()
	return rau
}

// SetTxHash sets the "tx_hash" field.
func (rau *ReceiveAddressUpdate) SetTxHash(s string) *ReceiveAddressUpdate {
	rau.mutation.SetTxHash(s)
	return rau
}

// SetNillableTxHash sets the "tx_hash" field if the given value is not nil.
func (rau *ReceiveAddressUpdate) SetNillableTxHash(s *string) *ReceiveAddressUpdate {
	if s != nil {
		rau.SetTxHash(*s)
	}
	return rau
}

// ClearTxHash clears the value of the "tx_hash" field.
func (rau *ReceiveAddressUpdate) ClearTxHash() *ReceiveAddressUpdate {
	rau.mutation.ClearTxHash()
	return rau
}

// SetValidUntil sets the "valid_until" field.
func (rau *ReceiveAddressUpdate) SetValidUntil(t time.Time) *ReceiveAddressUpdate {
	rau.mutation.SetValidUntil(t)
	return rau
}

// SetNillableValidUntil sets the "valid_until" field if the given value is not nil.
func (rau *ReceiveAddressUpdate) SetNillableValidUntil(t *time.Time) *ReceiveAddressUpdate {
	if t != nil {
		rau.SetValidUntil(*t)
	}
	return rau
}

// ClearValidUntil clears the value of the "valid_until" field.
func (rau *ReceiveAddressUpdate) ClearValidUntil() *ReceiveAddressUpdate {
	rau.mutation.ClearValidUntil()
	return rau
}

// SetPaymentOrderID sets the "payment_order" edge to the PaymentOrder entity by ID.
func (rau *ReceiveAddressUpdate) SetPaymentOrderID(id uuid.UUID) *ReceiveAddressUpdate {
	rau.mutation.SetPaymentOrderID(id)
	return rau
}

// SetNillablePaymentOrderID sets the "payment_order" edge to the PaymentOrder entity by ID if the given value is not nil.
func (rau *ReceiveAddressUpdate) SetNillablePaymentOrderID(id *uuid.UUID) *ReceiveAddressUpdate {
	if id != nil {
		rau = rau.SetPaymentOrderID(*id)
	}
	return rau
}

// SetPaymentOrder sets the "payment_order" edge to the PaymentOrder entity.
func (rau *ReceiveAddressUpdate) SetPaymentOrder(p *PaymentOrder) *ReceiveAddressUpdate {
	return rau.SetPaymentOrderID(p.ID)
}

// Mutation returns the ReceiveAddressMutation object of the builder.
func (rau *ReceiveAddressUpdate) Mutation() *ReceiveAddressMutation {
	return rau.mutation
}

// ClearPaymentOrder clears the "payment_order" edge to the PaymentOrder entity.
func (rau *ReceiveAddressUpdate) ClearPaymentOrder() *ReceiveAddressUpdate {
	rau.mutation.ClearPaymentOrder()
	return rau
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (rau *ReceiveAddressUpdate) Save(ctx context.Context) (int, error) {
	rau.defaults()
	return withHooks(ctx, rau.sqlSave, rau.mutation, rau.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (rau *ReceiveAddressUpdate) SaveX(ctx context.Context) int {
	affected, err := rau.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (rau *ReceiveAddressUpdate) Exec(ctx context.Context) error {
	_, err := rau.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rau *ReceiveAddressUpdate) ExecX(ctx context.Context) {
	if err := rau.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (rau *ReceiveAddressUpdate) defaults() {
	if _, ok := rau.mutation.UpdatedAt(); !ok {
		v := receiveaddress.UpdateDefaultUpdatedAt()
		rau.mutation.SetUpdatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (rau *ReceiveAddressUpdate) check() error {
	if v, ok := rau.mutation.Status(); ok {
		if err := receiveaddress.StatusValidator(v); err != nil {
			return &ValidationError{Name: "status", err: fmt.Errorf(`ent: validator failed for field "ReceiveAddress.status": %w`, err)}
		}
	}
	if v, ok := rau.mutation.TxHash(); ok {
		if err := receiveaddress.TxHashValidator(v); err != nil {
			return &ValidationError{Name: "tx_hash", err: fmt.Errorf(`ent: validator failed for field "ReceiveAddress.tx_hash": %w`, err)}
		}
	}
	return nil
}

func (rau *ReceiveAddressUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := rau.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(receiveaddress.Table, receiveaddress.Columns, sqlgraph.NewFieldSpec(receiveaddress.FieldID, field.TypeInt))
	if ps := rau.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := rau.mutation.UpdatedAt(); ok {
		_spec.SetField(receiveaddress.FieldUpdatedAt, field.TypeTime, value)
	}
	if value, ok := rau.mutation.Address(); ok {
		_spec.SetField(receiveaddress.FieldAddress, field.TypeString, value)
	}
	if value, ok := rau.mutation.Salt(); ok {
		_spec.SetField(receiveaddress.FieldSalt, field.TypeBytes, value)
	}
	if rau.mutation.SaltCleared() {
		_spec.ClearField(receiveaddress.FieldSalt, field.TypeBytes)
	}
	if value, ok := rau.mutation.Status(); ok {
		_spec.SetField(receiveaddress.FieldStatus, field.TypeEnum, value)
	}
	if value, ok := rau.mutation.LastIndexedBlock(); ok {
		_spec.SetField(receiveaddress.FieldLastIndexedBlock, field.TypeInt64, value)
	}
	if value, ok := rau.mutation.AddedLastIndexedBlock(); ok {
		_spec.AddField(receiveaddress.FieldLastIndexedBlock, field.TypeInt64, value)
	}
	if rau.mutation.LastIndexedBlockCleared() {
		_spec.ClearField(receiveaddress.FieldLastIndexedBlock, field.TypeInt64)
	}
	if value, ok := rau.mutation.LastUsed(); ok {
		_spec.SetField(receiveaddress.FieldLastUsed, field.TypeTime, value)
	}
	if rau.mutation.LastUsedCleared() {
		_spec.ClearField(receiveaddress.FieldLastUsed, field.TypeTime)
	}
	if value, ok := rau.mutation.TxHash(); ok {
		_spec.SetField(receiveaddress.FieldTxHash, field.TypeString, value)
	}
	if rau.mutation.TxHashCleared() {
		_spec.ClearField(receiveaddress.FieldTxHash, field.TypeString)
	}
	if value, ok := rau.mutation.ValidUntil(); ok {
		_spec.SetField(receiveaddress.FieldValidUntil, field.TypeTime, value)
	}
	if rau.mutation.ValidUntilCleared() {
		_spec.ClearField(receiveaddress.FieldValidUntil, field.TypeTime)
	}
	if rau.mutation.PaymentOrderCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   receiveaddress.PaymentOrderTable,
			Columns: []string{receiveaddress.PaymentOrderColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(paymentorder.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := rau.mutation.PaymentOrderIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   receiveaddress.PaymentOrderTable,
			Columns: []string{receiveaddress.PaymentOrderColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(paymentorder.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, rau.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{receiveaddress.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	rau.mutation.done = true
	return n, nil
}

// ReceiveAddressUpdateOne is the builder for updating a single ReceiveAddress entity.
type ReceiveAddressUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *ReceiveAddressMutation
}

// SetUpdatedAt sets the "updated_at" field.
func (rauo *ReceiveAddressUpdateOne) SetUpdatedAt(t time.Time) *ReceiveAddressUpdateOne {
	rauo.mutation.SetUpdatedAt(t)
	return rauo
}

// SetAddress sets the "address" field.
func (rauo *ReceiveAddressUpdateOne) SetAddress(s string) *ReceiveAddressUpdateOne {
	rauo.mutation.SetAddress(s)
	return rauo
}

// SetNillableAddress sets the "address" field if the given value is not nil.
func (rauo *ReceiveAddressUpdateOne) SetNillableAddress(s *string) *ReceiveAddressUpdateOne {
	if s != nil {
		rauo.SetAddress(*s)
	}
	return rauo
}

// SetSalt sets the "salt" field.
func (rauo *ReceiveAddressUpdateOne) SetSalt(b []byte) *ReceiveAddressUpdateOne {
	rauo.mutation.SetSalt(b)
	return rauo
}

// ClearSalt clears the value of the "salt" field.
func (rauo *ReceiveAddressUpdateOne) ClearSalt() *ReceiveAddressUpdateOne {
	rauo.mutation.ClearSalt()
	return rauo
}

// SetStatus sets the "status" field.
func (rauo *ReceiveAddressUpdateOne) SetStatus(r receiveaddress.Status) *ReceiveAddressUpdateOne {
	rauo.mutation.SetStatus(r)
	return rauo
}

// SetNillableStatus sets the "status" field if the given value is not nil.
func (rauo *ReceiveAddressUpdateOne) SetNillableStatus(r *receiveaddress.Status) *ReceiveAddressUpdateOne {
	if r != nil {
		rauo.SetStatus(*r)
	}
	return rauo
}

// SetLastIndexedBlock sets the "last_indexed_block" field.
func (rauo *ReceiveAddressUpdateOne) SetLastIndexedBlock(i int64) *ReceiveAddressUpdateOne {
	rauo.mutation.ResetLastIndexedBlock()
	rauo.mutation.SetLastIndexedBlock(i)
	return rauo
}

// SetNillableLastIndexedBlock sets the "last_indexed_block" field if the given value is not nil.
func (rauo *ReceiveAddressUpdateOne) SetNillableLastIndexedBlock(i *int64) *ReceiveAddressUpdateOne {
	if i != nil {
		rauo.SetLastIndexedBlock(*i)
	}
	return rauo
}

// AddLastIndexedBlock adds i to the "last_indexed_block" field.
func (rauo *ReceiveAddressUpdateOne) AddLastIndexedBlock(i int64) *ReceiveAddressUpdateOne {
	rauo.mutation.AddLastIndexedBlock(i)
	return rauo
}

// ClearLastIndexedBlock clears the value of the "last_indexed_block" field.
func (rauo *ReceiveAddressUpdateOne) ClearLastIndexedBlock() *ReceiveAddressUpdateOne {
	rauo.mutation.ClearLastIndexedBlock()
	return rauo
}

// SetLastUsed sets the "last_used" field.
func (rauo *ReceiveAddressUpdateOne) SetLastUsed(t time.Time) *ReceiveAddressUpdateOne {
	rauo.mutation.SetLastUsed(t)
	return rauo
}

// SetNillableLastUsed sets the "last_used" field if the given value is not nil.
func (rauo *ReceiveAddressUpdateOne) SetNillableLastUsed(t *time.Time) *ReceiveAddressUpdateOne {
	if t != nil {
		rauo.SetLastUsed(*t)
	}
	return rauo
}

// ClearLastUsed clears the value of the "last_used" field.
func (rauo *ReceiveAddressUpdateOne) ClearLastUsed() *ReceiveAddressUpdateOne {
	rauo.mutation.ClearLastUsed()
	return rauo
}

// SetTxHash sets the "tx_hash" field.
func (rauo *ReceiveAddressUpdateOne) SetTxHash(s string) *ReceiveAddressUpdateOne {
	rauo.mutation.SetTxHash(s)
	return rauo
}

// SetNillableTxHash sets the "tx_hash" field if the given value is not nil.
func (rauo *ReceiveAddressUpdateOne) SetNillableTxHash(s *string) *ReceiveAddressUpdateOne {
	if s != nil {
		rauo.SetTxHash(*s)
	}
	return rauo
}

// ClearTxHash clears the value of the "tx_hash" field.
func (rauo *ReceiveAddressUpdateOne) ClearTxHash() *ReceiveAddressUpdateOne {
	rauo.mutation.ClearTxHash()
	return rauo
}

// SetValidUntil sets the "valid_until" field.
func (rauo *ReceiveAddressUpdateOne) SetValidUntil(t time.Time) *ReceiveAddressUpdateOne {
	rauo.mutation.SetValidUntil(t)
	return rauo
}

// SetNillableValidUntil sets the "valid_until" field if the given value is not nil.
func (rauo *ReceiveAddressUpdateOne) SetNillableValidUntil(t *time.Time) *ReceiveAddressUpdateOne {
	if t != nil {
		rauo.SetValidUntil(*t)
	}
	return rauo
}

// ClearValidUntil clears the value of the "valid_until" field.
func (rauo *ReceiveAddressUpdateOne) ClearValidUntil() *ReceiveAddressUpdateOne {
	rauo.mutation.ClearValidUntil()
	return rauo
}

// SetPaymentOrderID sets the "payment_order" edge to the PaymentOrder entity by ID.
func (rauo *ReceiveAddressUpdateOne) SetPaymentOrderID(id uuid.UUID) *ReceiveAddressUpdateOne {
	rauo.mutation.SetPaymentOrderID(id)
	return rauo
}

// SetNillablePaymentOrderID sets the "payment_order" edge to the PaymentOrder entity by ID if the given value is not nil.
func (rauo *ReceiveAddressUpdateOne) SetNillablePaymentOrderID(id *uuid.UUID) *ReceiveAddressUpdateOne {
	if id != nil {
		rauo = rauo.SetPaymentOrderID(*id)
	}
	return rauo
}

// SetPaymentOrder sets the "payment_order" edge to the PaymentOrder entity.
func (rauo *ReceiveAddressUpdateOne) SetPaymentOrder(p *PaymentOrder) *ReceiveAddressUpdateOne {
	return rauo.SetPaymentOrderID(p.ID)
}

// Mutation returns the ReceiveAddressMutation object of the builder.
func (rauo *ReceiveAddressUpdateOne) Mutation() *ReceiveAddressMutation {
	return rauo.mutation
}

// ClearPaymentOrder clears the "payment_order" edge to the PaymentOrder entity.
func (rauo *ReceiveAddressUpdateOne) ClearPaymentOrder() *ReceiveAddressUpdateOne {
	rauo.mutation.ClearPaymentOrder()
	return rauo
}

// Where appends a list predicates to the ReceiveAddressUpdate builder.
func (rauo *ReceiveAddressUpdateOne) Where(ps ...predicate.ReceiveAddress) *ReceiveAddressUpdateOne {
	rauo.mutation.Where(ps...)
	return rauo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (rauo *ReceiveAddressUpdateOne) Select(field string, fields ...string) *ReceiveAddressUpdateOne {
	rauo.fields = append([]string{field}, fields...)
	return rauo
}

// Save executes the query and returns the updated ReceiveAddress entity.
func (rauo *ReceiveAddressUpdateOne) Save(ctx context.Context) (*ReceiveAddress, error) {
	rauo.defaults()
	return withHooks(ctx, rauo.sqlSave, rauo.mutation, rauo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (rauo *ReceiveAddressUpdateOne) SaveX(ctx context.Context) *ReceiveAddress {
	node, err := rauo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (rauo *ReceiveAddressUpdateOne) Exec(ctx context.Context) error {
	_, err := rauo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rauo *ReceiveAddressUpdateOne) ExecX(ctx context.Context) {
	if err := rauo.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (rauo *ReceiveAddressUpdateOne) defaults() {
	if _, ok := rauo.mutation.UpdatedAt(); !ok {
		v := receiveaddress.UpdateDefaultUpdatedAt()
		rauo.mutation.SetUpdatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (rauo *ReceiveAddressUpdateOne) check() error {
	if v, ok := rauo.mutation.Status(); ok {
		if err := receiveaddress.StatusValidator(v); err != nil {
			return &ValidationError{Name: "status", err: fmt.Errorf(`ent: validator failed for field "ReceiveAddress.status": %w`, err)}
		}
	}
	if v, ok := rauo.mutation.TxHash(); ok {
		if err := receiveaddress.TxHashValidator(v); err != nil {
			return &ValidationError{Name: "tx_hash", err: fmt.Errorf(`ent: validator failed for field "ReceiveAddress.tx_hash": %w`, err)}
		}
	}
	return nil
}

func (rauo *ReceiveAddressUpdateOne) sqlSave(ctx context.Context) (_node *ReceiveAddress, err error) {
	if err := rauo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(receiveaddress.Table, receiveaddress.Columns, sqlgraph.NewFieldSpec(receiveaddress.FieldID, field.TypeInt))
	id, ok := rauo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "ReceiveAddress.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := rauo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, receiveaddress.FieldID)
		for _, f := range fields {
			if !receiveaddress.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != receiveaddress.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := rauo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := rauo.mutation.UpdatedAt(); ok {
		_spec.SetField(receiveaddress.FieldUpdatedAt, field.TypeTime, value)
	}
	if value, ok := rauo.mutation.Address(); ok {
		_spec.SetField(receiveaddress.FieldAddress, field.TypeString, value)
	}
	if value, ok := rauo.mutation.Salt(); ok {
		_spec.SetField(receiveaddress.FieldSalt, field.TypeBytes, value)
	}
	if rauo.mutation.SaltCleared() {
		_spec.ClearField(receiveaddress.FieldSalt, field.TypeBytes)
	}
	if value, ok := rauo.mutation.Status(); ok {
		_spec.SetField(receiveaddress.FieldStatus, field.TypeEnum, value)
	}
	if value, ok := rauo.mutation.LastIndexedBlock(); ok {
		_spec.SetField(receiveaddress.FieldLastIndexedBlock, field.TypeInt64, value)
	}
	if value, ok := rauo.mutation.AddedLastIndexedBlock(); ok {
		_spec.AddField(receiveaddress.FieldLastIndexedBlock, field.TypeInt64, value)
	}
	if rauo.mutation.LastIndexedBlockCleared() {
		_spec.ClearField(receiveaddress.FieldLastIndexedBlock, field.TypeInt64)
	}
	if value, ok := rauo.mutation.LastUsed(); ok {
		_spec.SetField(receiveaddress.FieldLastUsed, field.TypeTime, value)
	}
	if rauo.mutation.LastUsedCleared() {
		_spec.ClearField(receiveaddress.FieldLastUsed, field.TypeTime)
	}
	if value, ok := rauo.mutation.TxHash(); ok {
		_spec.SetField(receiveaddress.FieldTxHash, field.TypeString, value)
	}
	if rauo.mutation.TxHashCleared() {
		_spec.ClearField(receiveaddress.FieldTxHash, field.TypeString)
	}
	if value, ok := rauo.mutation.ValidUntil(); ok {
		_spec.SetField(receiveaddress.FieldValidUntil, field.TypeTime, value)
	}
	if rauo.mutation.ValidUntilCleared() {
		_spec.ClearField(receiveaddress.FieldValidUntil, field.TypeTime)
	}
	if rauo.mutation.PaymentOrderCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   receiveaddress.PaymentOrderTable,
			Columns: []string{receiveaddress.PaymentOrderColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(paymentorder.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := rauo.mutation.PaymentOrderIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   receiveaddress.PaymentOrderTable,
			Columns: []string{receiveaddress.PaymentOrderColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(paymentorder.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &ReceiveAddress{config: rauo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, rauo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{receiveaddress.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	rauo.mutation.done = true
	return _node, nil
}
