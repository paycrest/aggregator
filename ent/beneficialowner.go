// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/ent/beneficialowner"
	"github.com/paycrest/aggregator/ent/kybprofile"
)

// BeneficialOwner is the model entity for the BeneficialOwner schema.
type BeneficialOwner struct {
	config `json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// FullName holds the value of the "full_name" field.
	FullName string `json:"full_name,omitempty"`
	// ResidentialAddress holds the value of the "residential_address" field.
	ResidentialAddress string `json:"residential_address,omitempty"`
	// ProofOfResidentialAddressURL holds the value of the "proof_of_residential_address_url" field.
	ProofOfResidentialAddressURL string `json:"proof_of_residential_address_url,omitempty"`
	// GovernmentIssuedIDURL holds the value of the "government_issued_id_url" field.
	GovernmentIssuedIDURL string `json:"government_issued_id_url,omitempty"`
	// DateOfBirth holds the value of the "date_of_birth" field.
	DateOfBirth string `json:"date_of_birth,omitempty"`
	// OwnershipPercentage holds the value of the "ownership_percentage" field.
	OwnershipPercentage float64 `json:"ownership_percentage,omitempty"`
	// GovernmentIssuedIDType holds the value of the "government_issued_id_type" field.
	GovernmentIssuedIDType beneficialowner.GovernmentIssuedIDType `json:"government_issued_id_type,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the BeneficialOwnerQuery when eager-loading is set.
	Edges                         BeneficialOwnerEdges `json:"edges"`
	kyb_profile_beneficial_owners *uuid.UUID
	selectValues                  sql.SelectValues
}

// BeneficialOwnerEdges holds the relations/edges for other nodes in the graph.
type BeneficialOwnerEdges struct {
	// KybProfile holds the value of the kyb_profile edge.
	KybProfile *KYBProfile `json:"kyb_profile,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// KybProfileOrErr returns the KybProfile value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e BeneficialOwnerEdges) KybProfileOrErr() (*KYBProfile, error) {
	if e.KybProfile != nil {
		return e.KybProfile, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: kybprofile.Label}
	}
	return nil, &NotLoadedError{edge: "kyb_profile"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*BeneficialOwner) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case beneficialowner.FieldOwnershipPercentage:
			values[i] = new(sql.NullFloat64)
		case beneficialowner.FieldFullName, beneficialowner.FieldResidentialAddress, beneficialowner.FieldProofOfResidentialAddressURL, beneficialowner.FieldGovernmentIssuedIDURL, beneficialowner.FieldDateOfBirth, beneficialowner.FieldGovernmentIssuedIDType:
			values[i] = new(sql.NullString)
		case beneficialowner.FieldID:
			values[i] = new(uuid.UUID)
		case beneficialowner.ForeignKeys[0]: // kyb_profile_beneficial_owners
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the BeneficialOwner fields.
func (bo *BeneficialOwner) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case beneficialowner.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				bo.ID = *value
			}
		case beneficialowner.FieldFullName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field full_name", values[i])
			} else if value.Valid {
				bo.FullName = value.String
			}
		case beneficialowner.FieldResidentialAddress:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field residential_address", values[i])
			} else if value.Valid {
				bo.ResidentialAddress = value.String
			}
		case beneficialowner.FieldProofOfResidentialAddressURL:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field proof_of_residential_address_url", values[i])
			} else if value.Valid {
				bo.ProofOfResidentialAddressURL = value.String
			}
		case beneficialowner.FieldGovernmentIssuedIDURL:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field government_issued_id_url", values[i])
			} else if value.Valid {
				bo.GovernmentIssuedIDURL = value.String
			}
		case beneficialowner.FieldDateOfBirth:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field date_of_birth", values[i])
			} else if value.Valid {
				bo.DateOfBirth = value.String
			}
		case beneficialowner.FieldOwnershipPercentage:
			if value, ok := values[i].(*sql.NullFloat64); !ok {
				return fmt.Errorf("unexpected type %T for field ownership_percentage", values[i])
			} else if value.Valid {
				bo.OwnershipPercentage = value.Float64
			}
		case beneficialowner.FieldGovernmentIssuedIDType:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field government_issued_id_type", values[i])
			} else if value.Valid {
				bo.GovernmentIssuedIDType = beneficialowner.GovernmentIssuedIDType(value.String)
			}
		case beneficialowner.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field kyb_profile_beneficial_owners", values[i])
			} else if value.Valid {
				bo.kyb_profile_beneficial_owners = new(uuid.UUID)
				*bo.kyb_profile_beneficial_owners = *value.S.(*uuid.UUID)
			}
		default:
			bo.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the BeneficialOwner.
// This includes values selected through modifiers, order, etc.
func (bo *BeneficialOwner) Value(name string) (ent.Value, error) {
	return bo.selectValues.Get(name)
}

// QueryKybProfile queries the "kyb_profile" edge of the BeneficialOwner entity.
func (bo *BeneficialOwner) QueryKybProfile() *KYBProfileQuery {
	return NewBeneficialOwnerClient(bo.config).QueryKybProfile(bo)
}

// Update returns a builder for updating this BeneficialOwner.
// Note that you need to call BeneficialOwner.Unwrap() before calling this method if this BeneficialOwner
// was returned from a transaction, and the transaction was committed or rolled back.
func (bo *BeneficialOwner) Update() *BeneficialOwnerUpdateOne {
	return NewBeneficialOwnerClient(bo.config).UpdateOne(bo)
}

// Unwrap unwraps the BeneficialOwner entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (bo *BeneficialOwner) Unwrap() *BeneficialOwner {
	_tx, ok := bo.config.driver.(*txDriver)
	if !ok {
		panic("ent: BeneficialOwner is not a transactional entity")
	}
	bo.config.driver = _tx.drv
	return bo
}

// String implements the fmt.Stringer.
func (bo *BeneficialOwner) String() string {
	var builder strings.Builder
	builder.WriteString("BeneficialOwner(")
	builder.WriteString(fmt.Sprintf("id=%v, ", bo.ID))
	builder.WriteString("full_name=")
	builder.WriteString(bo.FullName)
	builder.WriteString(", ")
	builder.WriteString("residential_address=")
	builder.WriteString(bo.ResidentialAddress)
	builder.WriteString(", ")
	builder.WriteString("proof_of_residential_address_url=")
	builder.WriteString(bo.ProofOfResidentialAddressURL)
	builder.WriteString(", ")
	builder.WriteString("government_issued_id_url=")
	builder.WriteString(bo.GovernmentIssuedIDURL)
	builder.WriteString(", ")
	builder.WriteString("date_of_birth=")
	builder.WriteString(bo.DateOfBirth)
	builder.WriteString(", ")
	builder.WriteString("ownership_percentage=")
	builder.WriteString(fmt.Sprintf("%v", bo.OwnershipPercentage))
	builder.WriteString(", ")
	builder.WriteString("government_issued_id_type=")
	builder.WriteString(fmt.Sprintf("%v", bo.GovernmentIssuedIDType))
	builder.WriteByte(')')
	return builder.String()
}

// BeneficialOwners is a parsable slice of BeneficialOwner.
type BeneficialOwners []*BeneficialOwner
