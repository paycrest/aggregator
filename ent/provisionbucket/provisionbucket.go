// Code generated by ent, DO NOT EDIT.

package provisionbucket

import (
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

const (
	// Label holds the string label denoting the provisionbucket type in the database.
	Label = "provision_bucket"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldMinAmount holds the string denoting the min_amount field in the database.
	FieldMinAmount = "min_amount"
	// FieldMaxAmount holds the string denoting the max_amount field in the database.
	FieldMaxAmount = "max_amount"
	// FieldCreatedAt holds the string denoting the created_at field in the database.
	FieldCreatedAt = "created_at"
	// EdgeCurrency holds the string denoting the currency edge name in mutations.
	EdgeCurrency = "currency"
	// EdgeLockPaymentOrders holds the string denoting the lock_payment_orders edge name in mutations.
	EdgeLockPaymentOrders = "lock_payment_orders"
	// EdgeProviderProfiles holds the string denoting the provider_profiles edge name in mutations.
	EdgeProviderProfiles = "provider_profiles"
	// Table holds the table name of the provisionbucket in the database.
	Table = "provision_buckets"
	// CurrencyTable is the table that holds the currency relation/edge.
	CurrencyTable = "provision_buckets"
	// CurrencyInverseTable is the table name for the FiatCurrency entity.
	// It exists in this package in order to avoid circular dependency with the "fiatcurrency" package.
	CurrencyInverseTable = "fiat_currencies"
	// CurrencyColumn is the table column denoting the currency relation/edge.
	CurrencyColumn = "fiat_currency_provision_buckets"
	// LockPaymentOrdersTable is the table that holds the lock_payment_orders relation/edge.
	LockPaymentOrdersTable = "lock_payment_orders"
	// LockPaymentOrdersInverseTable is the table name for the LockPaymentOrder entity.
	// It exists in this package in order to avoid circular dependency with the "lockpaymentorder" package.
	LockPaymentOrdersInverseTable = "lock_payment_orders"
	// LockPaymentOrdersColumn is the table column denoting the lock_payment_orders relation/edge.
	LockPaymentOrdersColumn = "provision_bucket_lock_payment_orders"
	// ProviderProfilesTable is the table that holds the provider_profiles relation/edge. The primary key declared below.
	ProviderProfilesTable = "provision_bucket_provider_profiles"
	// ProviderProfilesInverseTable is the table name for the ProviderProfile entity.
	// It exists in this package in order to avoid circular dependency with the "providerprofile" package.
	ProviderProfilesInverseTable = "provider_profiles"
)

// Columns holds all SQL columns for provisionbucket fields.
var Columns = []string{
	FieldID,
	FieldMinAmount,
	FieldMaxAmount,
	FieldCreatedAt,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "provision_buckets"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"fiat_currency_provision_buckets",
}

var (
	// ProviderProfilesPrimaryKey and ProviderProfilesColumn2 are the table columns denoting the
	// primary key for the provider_profiles relation (M2M).
	ProviderProfilesPrimaryKey = []string{"provision_bucket_id", "provider_profile_id"}
)

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	for i := range ForeignKeys {
		if column == ForeignKeys[i] {
			return true
		}
	}
	return false
}

var (
	// DefaultCreatedAt holds the default value on creation for the "created_at" field.
	DefaultCreatedAt func() time.Time
)

// OrderOption defines the ordering options for the ProvisionBucket queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByMinAmount orders the results by the min_amount field.
func ByMinAmount(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldMinAmount, opts...).ToFunc()
}

// ByMaxAmount orders the results by the max_amount field.
func ByMaxAmount(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldMaxAmount, opts...).ToFunc()
}

// ByCreatedAt orders the results by the created_at field.
func ByCreatedAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldCreatedAt, opts...).ToFunc()
}

// ByCurrencyField orders the results by currency field.
func ByCurrencyField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newCurrencyStep(), sql.OrderByField(field, opts...))
	}
}

// ByLockPaymentOrdersCount orders the results by lock_payment_orders count.
func ByLockPaymentOrdersCount(opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborsCount(s, newLockPaymentOrdersStep(), opts...)
	}
}

// ByLockPaymentOrders orders the results by lock_payment_orders terms.
func ByLockPaymentOrders(term sql.OrderTerm, terms ...sql.OrderTerm) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newLockPaymentOrdersStep(), append([]sql.OrderTerm{term}, terms...)...)
	}
}

// ByProviderProfilesCount orders the results by provider_profiles count.
func ByProviderProfilesCount(opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborsCount(s, newProviderProfilesStep(), opts...)
	}
}

// ByProviderProfiles orders the results by provider_profiles terms.
func ByProviderProfiles(term sql.OrderTerm, terms ...sql.OrderTerm) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newProviderProfilesStep(), append([]sql.OrderTerm{term}, terms...)...)
	}
}
func newCurrencyStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(CurrencyInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, CurrencyTable, CurrencyColumn),
	)
}
func newLockPaymentOrdersStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(LockPaymentOrdersInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2M, false, LockPaymentOrdersTable, LockPaymentOrdersColumn),
	)
}
func newProviderProfilesStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ProviderProfilesInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2M, false, ProviderProfilesTable, ProviderProfilesPrimaryKey...),
	)
}
