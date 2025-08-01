// Code generated by ent, DO NOT EDIT.

package user

import (
	"fmt"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/google/uuid"
)

const (
	// Label holds the string label denoting the user type in the database.
	Label = "user"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldCreatedAt holds the string denoting the created_at field in the database.
	FieldCreatedAt = "created_at"
	// FieldUpdatedAt holds the string denoting the updated_at field in the database.
	FieldUpdatedAt = "updated_at"
	// FieldFirstName holds the string denoting the first_name field in the database.
	FieldFirstName = "first_name"
	// FieldLastName holds the string denoting the last_name field in the database.
	FieldLastName = "last_name"
	// FieldEmail holds the string denoting the email field in the database.
	FieldEmail = "email"
	// FieldPassword holds the string denoting the password field in the database.
	FieldPassword = "password"
	// FieldScope holds the string denoting the scope field in the database.
	FieldScope = "scope"
	// FieldIsEmailVerified holds the string denoting the is_email_verified field in the database.
	FieldIsEmailVerified = "is_email_verified"
	// FieldHasEarlyAccess holds the string denoting the has_early_access field in the database.
	FieldHasEarlyAccess = "has_early_access"
	// FieldKybVerificationStatus holds the string denoting the kyb_verification_status field in the database.
	FieldKybVerificationStatus = "kyb_verification_status"
	// EdgeSenderProfile holds the string denoting the sender_profile edge name in mutations.
	EdgeSenderProfile = "sender_profile"
	// EdgeProviderProfile holds the string denoting the provider_profile edge name in mutations.
	EdgeProviderProfile = "provider_profile"
	// EdgeVerificationToken holds the string denoting the verification_token edge name in mutations.
	EdgeVerificationToken = "verification_token"
	// EdgeKybProfile holds the string denoting the kyb_profile edge name in mutations.
	EdgeKybProfile = "kyb_profile"
	// Table holds the table name of the user in the database.
	Table = "users"
	// SenderProfileTable is the table that holds the sender_profile relation/edge.
	SenderProfileTable = "sender_profiles"
	// SenderProfileInverseTable is the table name for the SenderProfile entity.
	// It exists in this package in order to avoid circular dependency with the "senderprofile" package.
	SenderProfileInverseTable = "sender_profiles"
	// SenderProfileColumn is the table column denoting the sender_profile relation/edge.
	SenderProfileColumn = "user_sender_profile"
	// ProviderProfileTable is the table that holds the provider_profile relation/edge.
	ProviderProfileTable = "provider_profiles"
	// ProviderProfileInverseTable is the table name for the ProviderProfile entity.
	// It exists in this package in order to avoid circular dependency with the "providerprofile" package.
	ProviderProfileInverseTable = "provider_profiles"
	// ProviderProfileColumn is the table column denoting the provider_profile relation/edge.
	ProviderProfileColumn = "user_provider_profile"
	// VerificationTokenTable is the table that holds the verification_token relation/edge.
	VerificationTokenTable = "verification_tokens"
	// VerificationTokenInverseTable is the table name for the VerificationToken entity.
	// It exists in this package in order to avoid circular dependency with the "verificationtoken" package.
	VerificationTokenInverseTable = "verification_tokens"
	// VerificationTokenColumn is the table column denoting the verification_token relation/edge.
	VerificationTokenColumn = "user_verification_token"
	// KybProfileTable is the table that holds the kyb_profile relation/edge.
	KybProfileTable = "kyb_profiles"
	// KybProfileInverseTable is the table name for the KYBProfile entity.
	// It exists in this package in order to avoid circular dependency with the "kybprofile" package.
	KybProfileInverseTable = "kyb_profiles"
	// KybProfileColumn is the table column denoting the kyb_profile relation/edge.
	KybProfileColumn = "user_kyb_profile"
)

// Columns holds all SQL columns for user fields.
var Columns = []string{
	FieldID,
	FieldCreatedAt,
	FieldUpdatedAt,
	FieldFirstName,
	FieldLastName,
	FieldEmail,
	FieldPassword,
	FieldScope,
	FieldIsEmailVerified,
	FieldHasEarlyAccess,
	FieldKybVerificationStatus,
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}

// Note that the variables below are initialized by the runtime
// package on the initialization of the application. Therefore,
// it should be imported in the main as follows:
//
//	import _ "github.com/paycrest/aggregator/ent/runtime"
var (
	Hooks [1]ent.Hook
	// DefaultCreatedAt holds the default value on creation for the "created_at" field.
	DefaultCreatedAt func() time.Time
	// DefaultUpdatedAt holds the default value on creation for the "updated_at" field.
	DefaultUpdatedAt func() time.Time
	// UpdateDefaultUpdatedAt holds the default value on update for the "updated_at" field.
	UpdateDefaultUpdatedAt func() time.Time
	// FirstNameValidator is a validator for the "first_name" field. It is called by the builders before save.
	FirstNameValidator func(string) error
	// LastNameValidator is a validator for the "last_name" field. It is called by the builders before save.
	LastNameValidator func(string) error
	// DefaultIsEmailVerified holds the default value on creation for the "is_email_verified" field.
	DefaultIsEmailVerified bool
	// DefaultHasEarlyAccess holds the default value on creation for the "has_early_access" field.
	DefaultHasEarlyAccess bool
	// DefaultID holds the default value on creation for the "id" field.
	DefaultID func() uuid.UUID
)

// KybVerificationStatus defines the type for the "kyb_verification_status" enum field.
type KybVerificationStatus string

// KybVerificationStatusNotStarted is the default value of the KybVerificationStatus enum.
const DefaultKybVerificationStatus = KybVerificationStatusNotStarted

// KybVerificationStatus values.
const (
	KybVerificationStatusNotStarted KybVerificationStatus = "not_started"
	KybVerificationStatusPending    KybVerificationStatus = "pending"
	KybVerificationStatusApproved   KybVerificationStatus = "approved"
	KybVerificationStatusRejected   KybVerificationStatus = "rejected"
)

func (kvs KybVerificationStatus) String() string {
	return string(kvs)
}

// KybVerificationStatusValidator is a validator for the "kyb_verification_status" field enum values. It is called by the builders before save.
func KybVerificationStatusValidator(kvs KybVerificationStatus) error {
	switch kvs {
	case KybVerificationStatusNotStarted, KybVerificationStatusPending, KybVerificationStatusApproved, KybVerificationStatusRejected:
		return nil
	default:
		return fmt.Errorf("user: invalid enum value for kyb_verification_status field: %q", kvs)
	}
}

// OrderOption defines the ordering options for the User queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByCreatedAt orders the results by the created_at field.
func ByCreatedAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldCreatedAt, opts...).ToFunc()
}

// ByUpdatedAt orders the results by the updated_at field.
func ByUpdatedAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldUpdatedAt, opts...).ToFunc()
}

// ByFirstName orders the results by the first_name field.
func ByFirstName(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldFirstName, opts...).ToFunc()
}

// ByLastName orders the results by the last_name field.
func ByLastName(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldLastName, opts...).ToFunc()
}

// ByEmail orders the results by the email field.
func ByEmail(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldEmail, opts...).ToFunc()
}

// ByPassword orders the results by the password field.
func ByPassword(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldPassword, opts...).ToFunc()
}

// ByScope orders the results by the scope field.
func ByScope(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldScope, opts...).ToFunc()
}

// ByIsEmailVerified orders the results by the is_email_verified field.
func ByIsEmailVerified(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldIsEmailVerified, opts...).ToFunc()
}

// ByHasEarlyAccess orders the results by the has_early_access field.
func ByHasEarlyAccess(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldHasEarlyAccess, opts...).ToFunc()
}

// ByKybVerificationStatus orders the results by the kyb_verification_status field.
func ByKybVerificationStatus(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldKybVerificationStatus, opts...).ToFunc()
}

// BySenderProfileField orders the results by sender_profile field.
func BySenderProfileField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newSenderProfileStep(), sql.OrderByField(field, opts...))
	}
}

// ByProviderProfileField orders the results by provider_profile field.
func ByProviderProfileField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newProviderProfileStep(), sql.OrderByField(field, opts...))
	}
}

// ByVerificationTokenCount orders the results by verification_token count.
func ByVerificationTokenCount(opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborsCount(s, newVerificationTokenStep(), opts...)
	}
}

// ByVerificationToken orders the results by verification_token terms.
func ByVerificationToken(term sql.OrderTerm, terms ...sql.OrderTerm) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newVerificationTokenStep(), append([]sql.OrderTerm{term}, terms...)...)
	}
}

// ByKybProfileField orders the results by kyb_profile field.
func ByKybProfileField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newKybProfileStep(), sql.OrderByField(field, opts...))
	}
}
func newSenderProfileStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(SenderProfileInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, false, SenderProfileTable, SenderProfileColumn),
	)
}
func newProviderProfileStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ProviderProfileInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, false, ProviderProfileTable, ProviderProfileColumn),
	)
}
func newVerificationTokenStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(VerificationTokenInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2M, false, VerificationTokenTable, VerificationTokenColumn),
	)
}
func newKybProfileStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(KybProfileInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, false, KybProfileTable, KybProfileColumn),
	)
}
