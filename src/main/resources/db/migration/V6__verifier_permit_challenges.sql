-- Aditivo: desafios de autorización de verificadores. No se habilita ningún usuario automáticamente.
CREATE TABLE wp_verifier_challenge (
  id uuid PRIMARY KEY,
  installation_id varchar(36) NOT NULL REFERENCES wp_installation(id) ON DELETE RESTRICT,
  entity_code varchar(32) NOT NULL,
  operation_hash char(64) NOT NULL CHECK (operation_hash ~ '^[0-9a-f]{64}$'),
  nonce_hash bytea NOT NULL CHECK (octet_length(nonce_hash) = 32),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX wp_verifier_challenge_pending_idx ON wp_verifier_challenge (expires_at)
WHERE consumed_at IS NULL;
