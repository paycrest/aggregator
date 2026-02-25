-- Enforce: when sponsorship_mode is 'self_sponsored', delegation_contract_address must be non-empty
ALTER TABLE "networks" ADD CONSTRAINT "networks_self_sponsored_requires_delegation_contract" CHECK (
  (sponsorship_mode <> 'self_sponsored') OR (delegation_contract_address <> '')
);
