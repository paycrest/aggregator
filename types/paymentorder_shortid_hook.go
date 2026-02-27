package types

import (
	"context"

	"entgo.io/ent"
	"github.com/google/uuid"
	gen "github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/hook"
	"github.com/paycrest/aggregator/ent/paymentorder"
)

// OnPaymentOrderTerminalStatus is called when a payment order's status changes to a terminal
// status (validated, settling, settled, refunding, refunded). It is set at init by the application
// (e.g. in utils/shortid) so that this package does not import utils/storage and create import cycles.
var OnPaymentOrderTerminalStatus func(context.Context, uuid.UUID)

// PaymentOrderDeleteShortIDMappingHook returns an ent hook that deletes the short_id_to_uuid
// Redis mapping when a PaymentOrder is updated (Update or UpdateOne) and status changes to a terminal status.
func PaymentOrderDeleteShortIDMappingHook() ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return hook.PaymentOrderFunc(func(ctx context.Context, m *gen.PaymentOrderMutation) (ent.Value, error) {
			v, err := next.Mutate(ctx, m)
			if err != nil {
				return v, err
			}
			status, ok := m.Status()
			if !ok || !isTerminalStatus(status) {
				return v, nil
			}
			if OnPaymentOrderTerminalStatus == nil {
				return v, nil
			}
			ids, err := m.IDs(ctx)
			if err != nil {
				return v, nil // don't fail the mutation for cleanup errors
			}
			for _, id := range ids {
				OnPaymentOrderTerminalStatus(ctx, id)
			}
			return v, nil
		})
	}
}

func isTerminalStatus(s paymentorder.Status) bool {
	switch s {
	case paymentorder.StatusValidated, paymentorder.StatusSettling, paymentorder.StatusSettled,
		paymentorder.StatusRefunding, paymentorder.StatusRefunded:
		return true
	default:
		return false
	}
}
