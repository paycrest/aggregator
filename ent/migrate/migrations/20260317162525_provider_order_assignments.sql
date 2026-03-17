-- Create "provider_order_assignments" table
CREATE TABLE "provider_order_assignments" (
  "id" uuid NOT NULL,
  "assignment_status" character varying NOT NULL DEFAULT 'assigned',
  "assigned_at" timestamptz NOT NULL,
  "reassigned_at" timestamptz NULL,
  "payment_order_provider_assignments" uuid NOT NULL,
  "provider_profile_order_assignments" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "provider_order_assignments_payment_orders_provider_assignments" FOREIGN KEY ("payment_order_provider_assignments") REFERENCES "payment_orders" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "provider_order_assignments_provider_profiles_order_assignments" FOREIGN KEY ("provider_profile_order_assignments") REFERENCES "provider_profiles" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION
);
-- Create index "providerorderassignment_assignment_status" to table: "provider_order_assignments"
CREATE INDEX "providerorderassignment_assignment_status" ON "provider_order_assignments" ("assignment_status");
-- Create index "providerorderassignment_paymen_3089e46cef598950b750c1fa4f88c89e" to table: "provider_order_assignments"
CREATE UNIQUE INDEX "providerorderassignment_paymen_3089e46cef598950b750c1fa4f88c89e" ON "provider_order_assignments" ("payment_order_provider_assignments", "provider_profile_order_assignments");
-- Add pk ranges for ('provider_order_assignments') tables
INSERT INTO "ent_types" ("type") VALUES ('provider_order_assignments');
