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
