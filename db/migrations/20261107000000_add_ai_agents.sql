-- migrate:up
-- AI agent accounts: real logins that coding agents test with, able to sign
-- in only while a superadmin has switched agent access on (Auth::
-- setAgentAccess()). agent_until is that switch, in UTC; NULL means never
-- switched (see the agent_access_default option).
ALTER TABLE users
  ADD COLUMN is_ai_agent TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN agent_until DATETIME NULL;

-- migrate:down
ALTER TABLE users DROP COLUMN is_ai_agent, DROP COLUMN agent_until;
