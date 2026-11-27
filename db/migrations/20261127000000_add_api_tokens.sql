-- migrate:up
-- API tokens (Auth::issueApiToken()): long-lived, revocable bearer tokens a
-- user makes for a device or script, each limited to named scopes (e.g.
-- admin:wall). Only the token's SHA-256 is stored, as with password_resets.
-- scopes is space-separated. expires_at NULL means no expiry.
CREATE TABLE api_tokens (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    name VARCHAR(80) NOT NULL,
    token_hash CHAR(64) NOT NULL,
    scopes VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NULL,
    last_used_at DATETIME NULL,
    revoked_at DATETIME NULL,
    UNIQUE KEY uniq_api_token_hash (token_hash),
    KEY idx_api_tokens_user (user_id),
    CONSTRAINT fk_api_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- migrate:down
DROP TABLE IF EXISTS api_tokens;
