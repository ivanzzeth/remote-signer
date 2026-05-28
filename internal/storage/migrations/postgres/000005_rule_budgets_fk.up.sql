-- Add foreign key constraint on rule_budgets.rule_id -> rules(id) ON DELETE CASCADE.
-- Clean orphan budgets first.
DELETE FROM rule_budgets WHERE rule_id NOT IN (SELECT id FROM rules);

ALTER TABLE rule_budgets DROP CONSTRAINT IF EXISTS fk_rule_budgets_rule;
ALTER TABLE rule_budgets ADD CONSTRAINT fk_rule_budgets_rule FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE;
