// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"database/sql/driver"
	"fmt"
	"math"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/lockpaymentorder"
	"github.com/paycrest/aggregator/ent/predicate"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/provisionbucket"
)

// ProvisionBucketQuery is the builder for querying ProvisionBucket entities.
type ProvisionBucketQuery struct {
	config
	ctx                   *QueryContext
	order                 []provisionbucket.OrderOption
	inters                []Interceptor
	predicates            []predicate.ProvisionBucket
	withCurrency          *FiatCurrencyQuery
	withLockPaymentOrders *LockPaymentOrderQuery
	withProviderProfiles  *ProviderProfileQuery
	withFKs               bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the ProvisionBucketQuery builder.
func (pbq *ProvisionBucketQuery) Where(ps ...predicate.ProvisionBucket) *ProvisionBucketQuery {
	pbq.predicates = append(pbq.predicates, ps...)
	return pbq
}

// Limit the number of records to be returned by this query.
func (pbq *ProvisionBucketQuery) Limit(limit int) *ProvisionBucketQuery {
	pbq.ctx.Limit = &limit
	return pbq
}

// Offset to start from.
func (pbq *ProvisionBucketQuery) Offset(offset int) *ProvisionBucketQuery {
	pbq.ctx.Offset = &offset
	return pbq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (pbq *ProvisionBucketQuery) Unique(unique bool) *ProvisionBucketQuery {
	pbq.ctx.Unique = &unique
	return pbq
}

// Order specifies how the records should be ordered.
func (pbq *ProvisionBucketQuery) Order(o ...provisionbucket.OrderOption) *ProvisionBucketQuery {
	pbq.order = append(pbq.order, o...)
	return pbq
}

// QueryCurrency chains the current query on the "currency" edge.
func (pbq *ProvisionBucketQuery) QueryCurrency() *FiatCurrencyQuery {
	query := (&FiatCurrencyClient{config: pbq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := pbq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := pbq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(provisionbucket.Table, provisionbucket.FieldID, selector),
			sqlgraph.To(fiatcurrency.Table, fiatcurrency.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, provisionbucket.CurrencyTable, provisionbucket.CurrencyColumn),
		)
		fromU = sqlgraph.SetNeighbors(pbq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryLockPaymentOrders chains the current query on the "lock_payment_orders" edge.
func (pbq *ProvisionBucketQuery) QueryLockPaymentOrders() *LockPaymentOrderQuery {
	query := (&LockPaymentOrderClient{config: pbq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := pbq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := pbq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(provisionbucket.Table, provisionbucket.FieldID, selector),
			sqlgraph.To(lockpaymentorder.Table, lockpaymentorder.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, provisionbucket.LockPaymentOrdersTable, provisionbucket.LockPaymentOrdersColumn),
		)
		fromU = sqlgraph.SetNeighbors(pbq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryProviderProfiles chains the current query on the "provider_profiles" edge.
func (pbq *ProvisionBucketQuery) QueryProviderProfiles() *ProviderProfileQuery {
	query := (&ProviderProfileClient{config: pbq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := pbq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := pbq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(provisionbucket.Table, provisionbucket.FieldID, selector),
			sqlgraph.To(providerprofile.Table, providerprofile.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, false, provisionbucket.ProviderProfilesTable, provisionbucket.ProviderProfilesPrimaryKey...),
		)
		fromU = sqlgraph.SetNeighbors(pbq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first ProvisionBucket entity from the query.
// Returns a *NotFoundError when no ProvisionBucket was found.
func (pbq *ProvisionBucketQuery) First(ctx context.Context) (*ProvisionBucket, error) {
	nodes, err := pbq.Limit(1).All(setContextOp(ctx, pbq.ctx, ent.OpQueryFirst))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{provisionbucket.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (pbq *ProvisionBucketQuery) FirstX(ctx context.Context) *ProvisionBucket {
	node, err := pbq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first ProvisionBucket ID from the query.
// Returns a *NotFoundError when no ProvisionBucket ID was found.
func (pbq *ProvisionBucketQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = pbq.Limit(1).IDs(setContextOp(ctx, pbq.ctx, ent.OpQueryFirstID)); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{provisionbucket.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (pbq *ProvisionBucketQuery) FirstIDX(ctx context.Context) int {
	id, err := pbq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single ProvisionBucket entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one ProvisionBucket entity is found.
// Returns a *NotFoundError when no ProvisionBucket entities are found.
func (pbq *ProvisionBucketQuery) Only(ctx context.Context) (*ProvisionBucket, error) {
	nodes, err := pbq.Limit(2).All(setContextOp(ctx, pbq.ctx, ent.OpQueryOnly))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{provisionbucket.Label}
	default:
		return nil, &NotSingularError{provisionbucket.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (pbq *ProvisionBucketQuery) OnlyX(ctx context.Context) *ProvisionBucket {
	node, err := pbq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only ProvisionBucket ID in the query.
// Returns a *NotSingularError when more than one ProvisionBucket ID is found.
// Returns a *NotFoundError when no entities are found.
func (pbq *ProvisionBucketQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = pbq.Limit(2).IDs(setContextOp(ctx, pbq.ctx, ent.OpQueryOnlyID)); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{provisionbucket.Label}
	default:
		err = &NotSingularError{provisionbucket.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (pbq *ProvisionBucketQuery) OnlyIDX(ctx context.Context) int {
	id, err := pbq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of ProvisionBuckets.
func (pbq *ProvisionBucketQuery) All(ctx context.Context) ([]*ProvisionBucket, error) {
	ctx = setContextOp(ctx, pbq.ctx, ent.OpQueryAll)
	if err := pbq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*ProvisionBucket, *ProvisionBucketQuery]()
	return withInterceptors[[]*ProvisionBucket](ctx, pbq, qr, pbq.inters)
}

// AllX is like All, but panics if an error occurs.
func (pbq *ProvisionBucketQuery) AllX(ctx context.Context) []*ProvisionBucket {
	nodes, err := pbq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of ProvisionBucket IDs.
func (pbq *ProvisionBucketQuery) IDs(ctx context.Context) (ids []int, err error) {
	if pbq.ctx.Unique == nil && pbq.path != nil {
		pbq.Unique(true)
	}
	ctx = setContextOp(ctx, pbq.ctx, ent.OpQueryIDs)
	if err = pbq.Select(provisionbucket.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (pbq *ProvisionBucketQuery) IDsX(ctx context.Context) []int {
	ids, err := pbq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (pbq *ProvisionBucketQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, pbq.ctx, ent.OpQueryCount)
	if err := pbq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, pbq, querierCount[*ProvisionBucketQuery](), pbq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (pbq *ProvisionBucketQuery) CountX(ctx context.Context) int {
	count, err := pbq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (pbq *ProvisionBucketQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, pbq.ctx, ent.OpQueryExist)
	switch _, err := pbq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (pbq *ProvisionBucketQuery) ExistX(ctx context.Context) bool {
	exist, err := pbq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the ProvisionBucketQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (pbq *ProvisionBucketQuery) Clone() *ProvisionBucketQuery {
	if pbq == nil {
		return nil
	}
	return &ProvisionBucketQuery{
		config:                pbq.config,
		ctx:                   pbq.ctx.Clone(),
		order:                 append([]provisionbucket.OrderOption{}, pbq.order...),
		inters:                append([]Interceptor{}, pbq.inters...),
		predicates:            append([]predicate.ProvisionBucket{}, pbq.predicates...),
		withCurrency:          pbq.withCurrency.Clone(),
		withLockPaymentOrders: pbq.withLockPaymentOrders.Clone(),
		withProviderProfiles:  pbq.withProviderProfiles.Clone(),
		// clone intermediate query.
		sql:  pbq.sql.Clone(),
		path: pbq.path,
	}
}

// WithCurrency tells the query-builder to eager-load the nodes that are connected to
// the "currency" edge. The optional arguments are used to configure the query builder of the edge.
func (pbq *ProvisionBucketQuery) WithCurrency(opts ...func(*FiatCurrencyQuery)) *ProvisionBucketQuery {
	query := (&FiatCurrencyClient{config: pbq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	pbq.withCurrency = query
	return pbq
}

// WithLockPaymentOrders tells the query-builder to eager-load the nodes that are connected to
// the "lock_payment_orders" edge. The optional arguments are used to configure the query builder of the edge.
func (pbq *ProvisionBucketQuery) WithLockPaymentOrders(opts ...func(*LockPaymentOrderQuery)) *ProvisionBucketQuery {
	query := (&LockPaymentOrderClient{config: pbq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	pbq.withLockPaymentOrders = query
	return pbq
}

// WithProviderProfiles tells the query-builder to eager-load the nodes that are connected to
// the "provider_profiles" edge. The optional arguments are used to configure the query builder of the edge.
func (pbq *ProvisionBucketQuery) WithProviderProfiles(opts ...func(*ProviderProfileQuery)) *ProvisionBucketQuery {
	query := (&ProviderProfileClient{config: pbq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	pbq.withProviderProfiles = query
	return pbq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		MinAmount decimal.Decimal `json:"min_amount,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.ProvisionBucket.Query().
//		GroupBy(provisionbucket.FieldMinAmount).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (pbq *ProvisionBucketQuery) GroupBy(field string, fields ...string) *ProvisionBucketGroupBy {
	pbq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &ProvisionBucketGroupBy{build: pbq}
	grbuild.flds = &pbq.ctx.Fields
	grbuild.label = provisionbucket.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		MinAmount decimal.Decimal `json:"min_amount,omitempty"`
//	}
//
//	client.ProvisionBucket.Query().
//		Select(provisionbucket.FieldMinAmount).
//		Scan(ctx, &v)
func (pbq *ProvisionBucketQuery) Select(fields ...string) *ProvisionBucketSelect {
	pbq.ctx.Fields = append(pbq.ctx.Fields, fields...)
	sbuild := &ProvisionBucketSelect{ProvisionBucketQuery: pbq}
	sbuild.label = provisionbucket.Label
	sbuild.flds, sbuild.scan = &pbq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a ProvisionBucketSelect configured with the given aggregations.
func (pbq *ProvisionBucketQuery) Aggregate(fns ...AggregateFunc) *ProvisionBucketSelect {
	return pbq.Select().Aggregate(fns...)
}

func (pbq *ProvisionBucketQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range pbq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, pbq); err != nil {
				return err
			}
		}
	}
	for _, f := range pbq.ctx.Fields {
		if !provisionbucket.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if pbq.path != nil {
		prev, err := pbq.path(ctx)
		if err != nil {
			return err
		}
		pbq.sql = prev
	}
	return nil
}

func (pbq *ProvisionBucketQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*ProvisionBucket, error) {
	var (
		nodes       = []*ProvisionBucket{}
		withFKs     = pbq.withFKs
		_spec       = pbq.querySpec()
		loadedTypes = [3]bool{
			pbq.withCurrency != nil,
			pbq.withLockPaymentOrders != nil,
			pbq.withProviderProfiles != nil,
		}
	)
	if pbq.withCurrency != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, provisionbucket.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*ProvisionBucket).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &ProvisionBucket{config: pbq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, pbq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := pbq.withCurrency; query != nil {
		if err := pbq.loadCurrency(ctx, query, nodes, nil,
			func(n *ProvisionBucket, e *FiatCurrency) { n.Edges.Currency = e }); err != nil {
			return nil, err
		}
	}
	if query := pbq.withLockPaymentOrders; query != nil {
		if err := pbq.loadLockPaymentOrders(ctx, query, nodes,
			func(n *ProvisionBucket) { n.Edges.LockPaymentOrders = []*LockPaymentOrder{} },
			func(n *ProvisionBucket, e *LockPaymentOrder) {
				n.Edges.LockPaymentOrders = append(n.Edges.LockPaymentOrders, e)
			}); err != nil {
			return nil, err
		}
	}
	if query := pbq.withProviderProfiles; query != nil {
		if err := pbq.loadProviderProfiles(ctx, query, nodes,
			func(n *ProvisionBucket) { n.Edges.ProviderProfiles = []*ProviderProfile{} },
			func(n *ProvisionBucket, e *ProviderProfile) {
				n.Edges.ProviderProfiles = append(n.Edges.ProviderProfiles, e)
			}); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (pbq *ProvisionBucketQuery) loadCurrency(ctx context.Context, query *FiatCurrencyQuery, nodes []*ProvisionBucket, init func(*ProvisionBucket), assign func(*ProvisionBucket, *FiatCurrency)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*ProvisionBucket)
	for i := range nodes {
		if nodes[i].fiat_currency_provision_buckets == nil {
			continue
		}
		fk := *nodes[i].fiat_currency_provision_buckets
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(fiatcurrency.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "fiat_currency_provision_buckets" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (pbq *ProvisionBucketQuery) loadLockPaymentOrders(ctx context.Context, query *LockPaymentOrderQuery, nodes []*ProvisionBucket, init func(*ProvisionBucket), assign func(*ProvisionBucket, *LockPaymentOrder)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[int]*ProvisionBucket)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
		if init != nil {
			init(nodes[i])
		}
	}
	query.withFKs = true
	query.Where(predicate.LockPaymentOrder(func(s *sql.Selector) {
		s.Where(sql.InValues(s.C(provisionbucket.LockPaymentOrdersColumn), fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.provision_bucket_lock_payment_orders
		if fk == nil {
			return fmt.Errorf(`foreign-key "provision_bucket_lock_payment_orders" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected referenced foreign-key "provision_bucket_lock_payment_orders" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}
func (pbq *ProvisionBucketQuery) loadProviderProfiles(ctx context.Context, query *ProviderProfileQuery, nodes []*ProvisionBucket, init func(*ProvisionBucket), assign func(*ProvisionBucket, *ProviderProfile)) error {
	edgeIDs := make([]driver.Value, len(nodes))
	byID := make(map[int]*ProvisionBucket)
	nids := make(map[string]map[*ProvisionBucket]struct{})
	for i, node := range nodes {
		edgeIDs[i] = node.ID
		byID[node.ID] = node
		if init != nil {
			init(node)
		}
	}
	query.Where(func(s *sql.Selector) {
		joinT := sql.Table(provisionbucket.ProviderProfilesTable)
		s.Join(joinT).On(s.C(providerprofile.FieldID), joinT.C(provisionbucket.ProviderProfilesPrimaryKey[1]))
		s.Where(sql.InValues(joinT.C(provisionbucket.ProviderProfilesPrimaryKey[0]), edgeIDs...))
		columns := s.SelectedColumns()
		s.Select(joinT.C(provisionbucket.ProviderProfilesPrimaryKey[0]))
		s.AppendSelect(columns...)
		s.SetDistinct(false)
	})
	if err := query.prepareQuery(ctx); err != nil {
		return err
	}
	qr := QuerierFunc(func(ctx context.Context, q Query) (Value, error) {
		return query.sqlAll(ctx, func(_ context.Context, spec *sqlgraph.QuerySpec) {
			assign := spec.Assign
			values := spec.ScanValues
			spec.ScanValues = func(columns []string) ([]any, error) {
				values, err := values(columns[1:])
				if err != nil {
					return nil, err
				}
				return append([]any{new(sql.NullInt64)}, values...), nil
			}
			spec.Assign = func(columns []string, values []any) error {
				outValue := int(values[0].(*sql.NullInt64).Int64)
				inValue := values[1].(*sql.NullString).String
				if nids[inValue] == nil {
					nids[inValue] = map[*ProvisionBucket]struct{}{byID[outValue]: {}}
					return assign(columns[1:], values[1:])
				}
				nids[inValue][byID[outValue]] = struct{}{}
				return nil
			}
		})
	})
	neighbors, err := withInterceptors[[]*ProviderProfile](ctx, query, qr, query.inters)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected "provider_profiles" node returned %v`, n.ID)
		}
		for kn := range nodes {
			assign(kn, n)
		}
	}
	return nil
}

func (pbq *ProvisionBucketQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := pbq.querySpec()
	_spec.Node.Columns = pbq.ctx.Fields
	if len(pbq.ctx.Fields) > 0 {
		_spec.Unique = pbq.ctx.Unique != nil && *pbq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, pbq.driver, _spec)
}

func (pbq *ProvisionBucketQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(provisionbucket.Table, provisionbucket.Columns, sqlgraph.NewFieldSpec(provisionbucket.FieldID, field.TypeInt))
	_spec.From = pbq.sql
	if unique := pbq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if pbq.path != nil {
		_spec.Unique = true
	}
	if fields := pbq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, provisionbucket.FieldID)
		for i := range fields {
			if fields[i] != provisionbucket.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := pbq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := pbq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := pbq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := pbq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (pbq *ProvisionBucketQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(pbq.driver.Dialect())
	t1 := builder.Table(provisionbucket.Table)
	columns := pbq.ctx.Fields
	if len(columns) == 0 {
		columns = provisionbucket.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if pbq.sql != nil {
		selector = pbq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if pbq.ctx.Unique != nil && *pbq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range pbq.predicates {
		p(selector)
	}
	for _, p := range pbq.order {
		p(selector)
	}
	if offset := pbq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := pbq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// ProvisionBucketGroupBy is the group-by builder for ProvisionBucket entities.
type ProvisionBucketGroupBy struct {
	selector
	build *ProvisionBucketQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (pbgb *ProvisionBucketGroupBy) Aggregate(fns ...AggregateFunc) *ProvisionBucketGroupBy {
	pbgb.fns = append(pbgb.fns, fns...)
	return pbgb
}

// Scan applies the selector query and scans the result into the given value.
func (pbgb *ProvisionBucketGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, pbgb.build.ctx, ent.OpQueryGroupBy)
	if err := pbgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*ProvisionBucketQuery, *ProvisionBucketGroupBy](ctx, pbgb.build, pbgb, pbgb.build.inters, v)
}

func (pbgb *ProvisionBucketGroupBy) sqlScan(ctx context.Context, root *ProvisionBucketQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(pbgb.fns))
	for _, fn := range pbgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*pbgb.flds)+len(pbgb.fns))
		for _, f := range *pbgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*pbgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := pbgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// ProvisionBucketSelect is the builder for selecting fields of ProvisionBucket entities.
type ProvisionBucketSelect struct {
	*ProvisionBucketQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (pbs *ProvisionBucketSelect) Aggregate(fns ...AggregateFunc) *ProvisionBucketSelect {
	pbs.fns = append(pbs.fns, fns...)
	return pbs
}

// Scan applies the selector query and scans the result into the given value.
func (pbs *ProvisionBucketSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, pbs.ctx, ent.OpQuerySelect)
	if err := pbs.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*ProvisionBucketQuery, *ProvisionBucketSelect](ctx, pbs.ProvisionBucketQuery, pbs, pbs.inters, v)
}

func (pbs *ProvisionBucketSelect) sqlScan(ctx context.Context, root *ProvisionBucketQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(pbs.fns))
	for _, fn := range pbs.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*pbs.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := pbs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
