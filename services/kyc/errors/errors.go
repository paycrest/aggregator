package errors

import "fmt"

// Common error types for KYC providers
type (
	ErrSignatureAlreadyUsed struct{}
	ErrAlreadyVerified      struct{}
	ErrProviderUnreachable  struct{ Err error }
	ErrProviderResponse     struct{ Err error }
	ErrDatabase             struct{ Err error }
	ErrNotFound             struct{}
	ErrNotVerified          struct{}
	ErrInvalidSecretKey     struct{}
	ErrKYCNotFound          struct{}
)

func (e ErrSignatureAlreadyUsed) Error() string {
	return "signature already used for identity verification"
}

func (e ErrAlreadyVerified) Error() string {
	return "this account has already been successfully verified"
}

func (e ErrProviderUnreachable) Error() string {
	return fmt.Sprintf("failed to request identity verification: couldn't reach identity provider: %v", e.Err)
}

func (e ErrProviderResponse) Error() string {
	return fmt.Sprintf("failed to request identity verification: %v", e.Err)
}

func (e ErrDatabase) Error() string {
	return fmt.Sprintf("database error: %v", e.Err)
}

func (e ErrNotFound) Error() string {
	return "no verification request found for this wallet address"
}

// Error implements the error interface for ErrNotVerified
func (e ErrNotVerified) Error() string {
	return "KYC not verified"
}

// Error implements the error interface for ErrInvalidSecretKey
func (e ErrInvalidSecretKey) Error() string {
	return "invalid secret key"
}

// Error implements the error interface for ErrKYCNotFound
func (e ErrKYCNotFound) Error() string {
	return "no KYC record found for wallet address"
}
