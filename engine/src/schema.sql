-- ExpertAuth engine schema v1. Independently authored from the baseline logical data model
-- (baseline/.../docs/CONFIGURATION_AND_DATA_MODEL.md). One write authority: this engine.

CREATE TABLE IF NOT EXISTS ea_schema_version (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE IF NOT EXISTS ea_apps (
  app_id      text PRIMARY KEY CHECK (app_id ~ '^[a-z0-9-]{1,64}$'),
  created_at  bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS ea_tenants (
  app_id                text NOT NULL REFERENCES ea_apps(app_id) ON DELETE CASCADE,
  tenant_id             text NOT NULL CHECK (tenant_id ~ '^[a-z0-9-]{1,64}$'),
  emailpassword_enabled boolean NOT NULL DEFAULT true,
  created_at            bigint NOT NULL,
  PRIMARY KEY (app_id, tenant_id)
);

-- Primary identity: stable user concept independent of any login method.
CREATE TABLE IF NOT EXISTS ea_users (
  app_id      text NOT NULL REFERENCES ea_apps(app_id) ON DELETE CASCADE,
  user_id     uuid NOT NULL,
  is_primary  boolean NOT NULL DEFAULT false,
  created_at  bigint NOT NULL,
  PRIMARY KEY (app_id, user_id)
);

-- Method identity: one login method, owned by exactly one primary user.
CREATE TABLE IF NOT EXISTS ea_login_methods (
  app_id          text NOT NULL,
  method_id       uuid NOT NULL,
  primary_user_id uuid NOT NULL,
  recipe_id       text NOT NULL CHECK (recipe_id IN ('emailpassword')),
  email           text,
  created_at      bigint NOT NULL,
  PRIMARY KEY (app_id, method_id),
  FOREIGN KEY (app_id, primary_user_id) REFERENCES ea_users(app_id, user_id) ON DELETE CASCADE
);

-- Explicit tenant membership; the same email is a distinct identity in each tenant unless shared here.
CREATE TABLE IF NOT EXISTS ea_tenant_methods (
  app_id     text NOT NULL,
  tenant_id  text NOT NULL,
  method_id  uuid NOT NULL,
  recipe_id  text NOT NULL,
  email      text,
  PRIMARY KEY (app_id, tenant_id, method_id),
  FOREIGN KEY (app_id, tenant_id) REFERENCES ea_tenants(app_id, tenant_id) ON DELETE CASCADE,
  FOREIGN KEY (app_id, method_id) REFERENCES ea_login_methods(app_id, method_id) ON DELETE CASCADE
);
-- Tenant-scoped identifier uniqueness; deliberately no global unique email.
CREATE UNIQUE INDEX IF NOT EXISTS ea_tenant_methods_email
  ON ea_tenant_methods (app_id, tenant_id, recipe_id, email) WHERE email IS NOT NULL;

-- Credential: protected verifier, never returned by any API.
CREATE TABLE IF NOT EXISTS ea_password_credentials (
  app_id        text NOT NULL,
  method_id     uuid NOT NULL,
  password_hash text NOT NULL,
  updated_at    bigint NOT NULL,
  PRIMARY KEY (app_id, method_id),
  FOREIGN KEY (app_id, method_id) REFERENCES ea_login_methods(app_id, method_id) ON DELETE CASCADE
);

-- One-time challenge (password reset). Only the SHA-256 of the token is stored.
CREATE TABLE IF NOT EXISTS ea_reset_tokens (
  app_id      text NOT NULL,
  token_hash  text NOT NULL,
  tenant_id   text NOT NULL,
  method_id   uuid NOT NULL,
  email       text NOT NULL,
  expires_at  bigint NOT NULL,
  PRIMARY KEY (app_id, token_hash),
  FOREIGN KEY (app_id, method_id) REFERENCES ea_login_methods(app_id, method_id) ON DELETE CASCADE
);

-- Session and its refresh state machine. Refresh tokens are never stored, only SHA-256 digests.
CREATE TABLE IF NOT EXISTS ea_sessions (
  app_id                text NOT NULL,
  session_handle        uuid NOT NULL,
  tenant_id             text NOT NULL,
  user_id               text NOT NULL,
  recipe_user_id        text NOT NULL,
  jwt_data              jsonb NOT NULL,
  session_data          jsonb NOT NULL,
  anti_csrf_token       text,
  current_refresh_hash  text NOT NULL,
  previous_refresh_hash text,
  previous_valid_until  bigint,
  generation            integer NOT NULL DEFAULT 0,
  created_at            bigint NOT NULL,
  expires_at            bigint NOT NULL,
  revoked_at            bigint,
  revoked_reason        text,
  PRIMARY KEY (app_id, session_handle),
  FOREIGN KEY (app_id, tenant_id) REFERENCES ea_tenants(app_id, tenant_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS ea_sessions_current ON ea_sessions (app_id, current_refresh_hash);
CREATE INDEX IF NOT EXISTS ea_sessions_user ON ea_sessions (app_id, user_id);
CREATE INDEX IF NOT EXISTS ea_sessions_previous ON ea_sessions (app_id, previous_refresh_hash) WHERE previous_refresh_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS ea_sessions_recipe_user ON ea_sessions (app_id, recipe_user_id);

-- Every refresh token ever superseded, for replay (theft) detection.
CREATE TABLE IF NOT EXISTS ea_refresh_history (
  app_id         text NOT NULL,
  token_hash     text NOT NULL,
  session_handle uuid NOT NULL,
  PRIMARY KEY (app_id, token_hash),
  FOREIGN KEY (app_id, session_handle) REFERENCES ea_sessions(app_id, session_handle) ON DELETE CASCADE
);

-- Signing keys; private material is AES-256-GCM encrypted with the operator key-encryption key.
CREATE TABLE IF NOT EXISTS ea_signing_keys (
  app_id        text NOT NULL REFERENCES ea_apps(app_id) ON DELETE CASCADE,
  key_id        text NOT NULL,
  algorithm     text NOT NULL CHECK (algorithm = 'RS256'),
  public_jwk    jsonb NOT NULL,
  private_enc   text NOT NULL,
  created_at    bigint NOT NULL,
  PRIMARY KEY (app_id, key_id)
);
