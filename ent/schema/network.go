package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/shopspring/decimal"
)

// Network holds the schema definition for the Network entity.
type Network struct {
	ent.Schema
}

// Mixin of the Network.
func (Network) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Fields of the Network.
func (Network) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("chain_id"),
		// e.g "bnb-smart-chain", "base", "arbitrum-one", "polygon", "ethereum", "ethereum-sepolia", "tron-shasta", "tron"
		field.String("identifier").
			Unique(),
		field.String("rpc_endpoint"),
		field.String("gateway_contract_address").Default(""),
		field.String("delegation_contract_address").Default(""),
		field.Enum("wallet_service").
			Values("engine", "native").
			Default("engine"),
		field.Float("block_time").
			GoType(decimal.Decimal{}),
		field.Bool("is_testnet"),
		field.String("bundler_url").
			Optional(),
		field.String("paymaster_url").
			Optional(),
		field.Float("fee").
			GoType(decimal.Decimal{}),
	}
}

// Edges of the Network.
func (Network) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("tokens", Token.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("payment_webhook", PaymentWebhook.Type).
			Unique(),
	}
}
