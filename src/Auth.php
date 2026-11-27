<?php

declare(strict_types=1);

namespace Coder999\LoginKit;

use PDO;

final class Auth
{
    /** The role that passes every hasRole() check. */
    public const SUPERADMIN = 'superadmin';

    /** lastRefusal(): the credential was right, but AI agent access is off. */
    public const AGENT_ACCESS_OFF = 'agent_access_off';

    private PDO $pdo;
    private string $cookieName;
    private string $cookieDomain;
    private bool $cookieSecure;
    private int $loginMaxAttempts;
    private int $loginWindowSeconds;
    private bool $agentAccessDefault;
    private int $sessionLifetime;
    private ?string $lastRefusal = null;

    public function __construct(PDO $pdo, array $options = [])
    {
        $this->pdo = $pdo;
        $this->cookieName = $options['cookie_name'] ?? 'identity_session';
        // '' (host-only) matches marktuttlemd's current live cookie
        // behavior — callers pass '.marktuttlemd.com' / '.nexus.local'
        // only once they're ready for cross-subdomain sharing.
        $this->cookieDomain = $options['cookie_domain'] ?? '';
        $this->cookieSecure = $options['cookie_secure'] ?? true;
        $this->loginMaxAttempts = $options['login_max_attempts'] ?? 8;
        $this->loginWindowSeconds = $options['login_window_seconds'] ?? 900;
        // Whether AI agents may sign in before a superadmin has ever used
        // setAgentAccess(). Pass true in local dev only.
        $this->agentAccessDefault = $options['agent_access_default'] ?? false;
        // Seconds a sign-in lasts. 0: until the browser closes, or PHP's
        // session.gc_maxlifetime (24 min by default) of idleness.
        $this->sessionLifetime = $options['session_lifetime'] ?? 0;
    }

    /**
     * Install the database session handler and return a ready Auth.
     *
     * The handler only takes effect for sessions started after it is
     * installed, so this refuses to run once a session is already active
     * rather than silently leaving that request on file-based sessions.
     */
    public static function bootstrap(PDO $pdo, array $options = []): self
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            throw new \LogicException('Auth::bootstrap() must run before any session is started.');
        }
        session_set_save_handler(new DbSessionHandler($pdo), true);
        return new self($pdo, $options);
    }

    public function sessionStart(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }
        session_name($this->cookieName);
        if ($this->sessionLifetime > 0) {
            ini_set('session.gc_maxlifetime', (string)$this->sessionLifetime);
        }
        session_set_cookie_params([
            'lifetime' => $this->sessionLifetime,
            'path'     => '/',
            'domain'   => $this->cookieDomain,
            'secure'   => $this->cookieSecure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        session_start();
    }

    public function currentUser(): ?array
    {
        $this->sessionStart();
        if (empty($_SESSION['user_id'])) {
            return null;
        }
        $st = $this->pdo->prepare('SELECT id, username, role, last_login, is_ai_agent FROM users WHERE id = ?');
        $st->execute([$_SESSION['user_id']]);
        $user = $st->fetch(PDO::FETCH_ASSOC);
        if ($user === false) {
            return null;
        }
        $user['id'] = (int)$user['id'];
        $user['is_ai_agent'] = (bool)$user['is_ai_agent'];
        if ($user['is_ai_agent'] && $this->agentAccessUntil() === null) {
            unset($_SESSION['user_id']);    // switching access off ends a live agent session too
            return null;
        }
        return $user;
    }

    public function requireLogin(string $loginUrl = 'login.php'): array
    {
        $user = $this->currentUser();
        if ($user === null) {
            header('Location: ' . $loginUrl);
            exit;
        }
        return $user;
    }

    /**
     * Whether the signed-in user holds $role. SUPERADMIN holds every role.
     * Role names are the consuming app's own; this library defines only
     * SUPERADMIN.
     */
    public function hasRole(string $role): bool
    {
        $user = $this->currentUser();
        return $user !== null && ($user['role'] === $role || $user['role'] === self::SUPERADMIN);
    }

    public function requireRole(string $role, string $loginUrl = 'login.php'): array
    {
        $user = $this->requireLogin($loginUrl);
        if (!$this->hasRole($role)) {
            http_response_code(403);
            exit('You do not have access to this page.');
        }
        return $user;
    }

    public function csrfToken(): string
    {
        $this->sessionStart();
        if (empty($_SESSION['csrf'])) {
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf'];
    }

    public function csrfField(): string
    {
        return '<input type="hidden" name="csrf" value="' . htmlspecialchars($this->csrfToken()) . '">';
    }

    public function csrfCheck(): void
    {
        $this->sessionStart();
        $sent = $_POST['csrf'] ?? '';
        if (empty($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], (string)$sent)) {
            http_response_code(400);
            exit('Invalid or expired form token. Go back, reload the page, and try again.');
        }
    }

    public function clientIp(): string
    {
        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }

    public function loginThrottled(): bool
    {
        $cutoff = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))
            ->modify("-{$this->loginWindowSeconds} seconds")
            ->format('Y-m-d H:i:s');
        $st = $this->pdo->prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND attempted_at > ?');
        $st->execute([$this->clientIp(), $cutoff]);
        return (int)$st->fetch(PDO::FETCH_ASSOC)['n'] >= $this->loginMaxAttempts;
    }

    /**
     * Record one failed authentication against this client IP.
     *
     * Public so a consumer adding its own credential type (a passkey
     * assertion, say) can feed the same budget `attemptLogin()` uses,
     * rather than reaching into `login_attempts` itself and taking a
     * second copy of this schema with it.
     */
    public function noteLoginFailure(): void
    {
        $now = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        $this->pdo->prepare('INSERT INTO login_attempts (ip, attempted_at) VALUES (?, ?)')
            ->execute([$this->clientIp(), $now]);
    }

    /** Clear this client IP's failures. Call after a successful login. */
    public function clearLoginFailures(): void
    {
        $this->pdo->prepare('DELETE FROM login_attempts WHERE ip = ?')->execute([$this->clientIp()]);
    }

    public function attemptLogin(string $username, string $password): bool
    {
        $this->sessionStart();
        $this->lastRefusal = null;
        $st = $this->pdo->prepare('SELECT * FROM users WHERE username = ?');
        $st->execute([$username]);
        $user = $st->fetch(PDO::FETCH_ASSOC);

        // A NULL password_hash is an account that has no password yet (an app
        // inviting people before they choose one): never a match.
        if ($user !== false && $user['password_hash'] !== null && password_verify($password, $user['password_hash'])) {
            $this->clearLoginFailures();
            // loginAs() owns the whole "establish a session" step, including
            // deciding the user still exists. Reporting success when it
            // declined would hand the caller a logged-in user with no
            // session. Not counted as a failed attempt: the credential was
            // correct, so rate-limiting this address would be wrong.
            return $this->loginAs((int)$user['id']);
        }

        $this->noteLoginFailure();
        return false;
    }

    /**
     * Establish a logged-in session for a user id.
     *
     * DANGER: this verifies NO credential. It is the shared tail of every
     * authentication path (password, passkey), and calling it directly
     * from application code is an authentication bypass. Only call it
     * after you have actually authenticated the user by some means.
     */
    public function loginAs(int $userId): bool
    {
        $this->sessionStart();
        $this->lastRefusal = null;
        $st = $this->pdo->prepare('SELECT id, is_ai_agent FROM users WHERE id = ?');
        $st->execute([$userId]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            return false;
        }
        if ($row['is_ai_agent'] && $this->agentAccessUntil() === null) {
            $this->lastRefusal = self::AGENT_ACCESS_OFF;
            return false;
        }
        session_regenerate_id(true);
        $_SESSION['user_id'] = $userId;
        $now = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        $this->pdo->prepare('UPDATE users SET last_login = ? WHERE id = ?')->execute([$now, $userId]);
        return true;
    }

    /**
     * Start a password reset. Returns a single-use token, good for an hour,
     * or null when there is no such account or the request is throttled.
     *
     * The caller emails a link carrying the token and must answer the same
     * way whether or not it got one, so the page doesn't reveal which
     * addresses have accounts. Each request spends this client IP's
     * failed-login budget (see loginThrottled()), and one account gets at
     * most three tokens an hour, so the form can't be used to flood an
     * inbox. Only the token's SHA-256 is stored.
     */
    public function requestPasswordReset(string $username): ?string
    {
        if ($this->loginThrottled()) {
            return null;
        }
        $this->noteLoginFailure();
        $st = $this->pdo->prepare('SELECT id FROM users WHERE username = ?');
        $st->execute([$username]);
        $user = $st->fetch(PDO::FETCH_ASSOC);
        if ($user === false) {
            return null;
        }
        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $st = $this->pdo->prepare('SELECT COUNT(*) AS n FROM password_resets WHERE user_id = ? AND created_at > ?');
        $st->execute([$user['id'], $now->modify('-1 hour')->format('Y-m-d H:i:s')]);
        if ((int)$st->fetch(PDO::FETCH_ASSOC)['n'] >= 3) {
            return null;
        }
        return $this->insertToken((int)$user['id'], 1);
    }

    /**
     * Issue a set-password token for an account an administrator is
     * inviting, good for $ttlHours (at most 30 days). The token is finished
     * exactly like a reset: passwordResetUser(), then resetPassword().
     *
     * Unlike requestPasswordReset() this is not throttled and spends no
     * failed-login budget, because no visitor asked for it. Call it ONLY from
     * a page restricted to an administrator; a form anyone can reach must use
     * requestPasswordReset(). Throws for an unknown user id or a bad TTL.
     * Only the token's SHA-256 is stored.
     */
    public function issueSetPasswordToken(int $userId, int $ttlHours): string
    {
        if ($ttlHours < 1 || $ttlHours > 720) {
            throw new \InvalidArgumentException('ttlHours must be between 1 and 720.');
        }
        $st = $this->pdo->prepare('SELECT id FROM users WHERE id = ?');
        $st->execute([$userId]);
        if ($st->fetch(PDO::FETCH_ASSOC) === false) {
            throw new \InvalidArgumentException("No user $userId.");
        }
        return $this->insertToken($userId, $ttlHours);
    }

    private function insertToken(int $userId, int $ttlHours): string
    {
        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $token = bin2hex(random_bytes(32));
        $this->pdo->prepare('INSERT INTO password_resets (user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)')
            ->execute([$userId, hash('sha256', $token), $now->format('Y-m-d H:i:s'),
                       $now->modify("+$ttlHours hours")->format('Y-m-d H:i:s')]);
        return $token;
    }

    /** The user id a reset token is good for, or null if it is unknown, used or expired. */
    public function passwordResetUser(string $token): ?int
    {
        $now = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        $st = $this->pdo->prepare('SELECT user_id FROM password_resets WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?');
        $st->execute([hash('sha256', $token), $now]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        return $row === false ? null : (int)$row['user_id'];
    }

    /**
     * Finish a reset: set the new password, spend every outstanding token
     * for the account, and end all of its sessions (whoever had the old
     * password may be signed in). Returns false for a bad token. Password
     * rules (length and so on) are the caller's to check first.
     */
    public function resetPassword(string $token, string $newPassword): bool
    {
        $userId = $this->passwordResetUser($token);
        if ($userId === null) {
            return false;
        }
        $now = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        $this->pdo->beginTransaction();
        try {
            $this->pdo->prepare('UPDATE users SET password_hash = ? WHERE id = ?')
                ->execute([password_hash($newPassword, PASSWORD_DEFAULT), $userId]);
            $this->pdo->prepare('UPDATE password_resets SET used_at = ? WHERE user_id = ? AND used_at IS NULL')
                ->execute([$now, $userId]);
            // Session data is PHP's own serialization: "user_id|i:5;" at the
            // start of the data or straight after the previous value.
            $key = "user_id|i:$userId;";
            $this->pdo->prepare('DELETE FROM sessions WHERE data LIKE ? OR data LIKE ? OR data LIKE ?')
                ->execute(["$key%", "%;$key%", "%}$key%"]);
            $this->pdo->commit();
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
        return true;
    }

    /**
     * Why the last attemptLogin()/loginAs() (or passkey sign-in) refused a
     * correct credential: AGENT_ACCESS_OFF, or null. Only meaningful right
     * after a refusal, so a page can say "agent access is off" without
     * revealing which addresses are agents to someone without the password.
     */
    public function lastRefusal(): ?string
    {
        return $this->lastRefusal;
    }

    /**
     * Until when AI agent accounts (users.is_ai_agent) may sign in, as a UTC
     * 'Y-m-d H:i:s', or null for not now. Never switched: '9999-12-31
     * 23:59:59' with the agent_access_default option, else null.
     */
    public function agentAccessUntil(): ?string
    {
        $until = $this->pdo->query('SELECT MAX(agent_until) FROM users WHERE is_ai_agent = 1')->fetchColumn();
        if ($until === null || $until === false) {
            return $this->agentAccessDefault ? '9999-12-31 23:59:59' : null;
        }
        return $until > $this->utc() ? $until : null;
    }

    /**
     * Switch AI agent sign-in on for $hours, or off with 0 (which also ends
     * agents' live sessions on their next request). Only a superadmin who
     * is not an agent may: an agent must never extend its own access.
     * Returns false, changing nothing, for anyone else.
     */
    public function setAgentAccess(int $hours): bool
    {
        $me = $this->currentUser();
        if ($me === null || $me['role'] !== self::SUPERADMIN || $me['is_ai_agent']) {
            return false;
        }
        // Off is a past time, not NULL, so agent_access_default can't switch it back on.
        $this->pdo->prepare('UPDATE users SET agent_until = ? WHERE is_ai_agent = 1')
            ->execute([$this->utc($hours > 0 ? $hours * 3600 : -1)]);
        return true;
    }

    /** Every API token starts with this, so a leaked one is recognisable (and greppable). */
    public const API_TOKEN_PREFIX = 'lkt_';

    /**
     * Make an API token for the signed-in user: a long-lived bearer token
     * for a device or script, good only for $scopes (each like 'admin:wall':
     * lowercase letters, digits, ':', '_', '-'), for $ttlDays or with no
     * expiry. Returns the token, which is shown once and never stored, or
     * null, changing nothing, when no one is signed in or the signed-in
     * account is an AI agent (an agent must never mint its own access).
     * Throws for a bad name, scope or TTL.
     *
     * The caller decides who may reach this at all (admin keeps it on a
     * superadmin page) and which scopes a page may offer.
     */
    public function issueApiToken(string $name, array $scopes, ?int $ttlDays = null): ?string
    {
        $name = trim($name);
        if ($name === '' || mb_strlen($name) > 80) {
            throw new \InvalidArgumentException('A token name is 1 to 80 characters.');
        }
        $scopes = array_values(array_unique($scopes));
        if ($scopes === [] || array_filter($scopes, static fn ($s) => !is_string($s) || !preg_match('/^[a-z0-9:_-]{1,40}$/', $s))
            || strlen(implode(' ', $scopes)) > 255) {
            throw new \InvalidArgumentException('Scopes are 1 to 40 of a-z 0-9 : _ - each.');
        }
        if ($ttlDays !== null && ($ttlDays < 1 || $ttlDays > 3650)) {
            throw new \InvalidArgumentException('ttlDays must be between 1 and 3650.');
        }
        $me = $this->currentUser();
        if ($me === null || $me['is_ai_agent']) {
            return null;
        }
        $token = self::API_TOKEN_PREFIX . bin2hex(random_bytes(32));
        $this->pdo->prepare('INSERT INTO api_tokens (user_id, name, token_hash, scopes, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
            ->execute([$me['id'], $name, hash('sha256', $token), implode(' ', $scopes), $this->utc(),
                       $ttlDays === null ? null : $this->utc($ttlDays * 86400)]);
        return $token;
    }

    /**
     * The signed-in user's API tokens, newest first, without their hashes:
     * id, name, scopes (list), created_at, expires_at, last_used_at,
     * revoked_at (UTC 'Y-m-d H:i:s' or null). [] when no one is signed in.
     */
    public function apiTokens(): array
    {
        $me = $this->currentUser();
        if ($me === null) {
            return [];
        }
        $st = $this->pdo->prepare('SELECT id, name, scopes, created_at, expires_at, last_used_at, revoked_at FROM api_tokens WHERE user_id = ? ORDER BY id DESC');
        $st->execute([$me['id']]);
        return array_map(static fn ($r) => ['id' => (int)$r['id'], 'scopes' => explode(' ', $r['scopes'])] + $r, $st->fetchAll(PDO::FETCH_ASSOC));
    }

    /**
     * Revoke one of the signed-in user's tokens, effective on its next use.
     * False, changing nothing, for no one signed in, an AI agent, someone
     * else's token, or one already revoked.
     */
    public function revokeApiToken(int $tokenId): bool
    {
        $me = $this->currentUser();
        if ($me === null || $me['is_ai_agent']) {
            return false;
        }
        $st = $this->pdo->prepare('UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL');
        $st->execute([$this->utc(), $tokenId, $me['id']]);
        return $st->rowCount() === 1;
    }

    /**
     * Who an API token speaks for, if it is good for $scope: the owner's id,
     * username and role plus token_id and token_name, or null for a
     * malformed, unknown, revoked or expired token, one without $scope, or
     * one whose owner is (now) an AI agent. Reads no session and starts
     * none: call it from bearer-only endpoints. Notes last_used_at, at most
     * once a minute.
     */
    public function apiTokenUser(string $token, string $scope): ?array
    {
        if (!preg_match('/^' . self::API_TOKEN_PREFIX . '[0-9a-f]{64}$/', $token)) {
            return null;
        }
        $st = $this->pdo->prepare('SELECT t.id AS token_id, t.name AS token_name, t.scopes, t.expires_at, t.revoked_at, t.last_used_at,
            u.id, u.username, u.role, u.is_ai_agent FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?');
        $st->execute([hash('sha256', $token)]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        $now = $this->utc();
        if ($row === false || $row['revoked_at'] !== null || ($row['expires_at'] !== null && $row['expires_at'] <= $now)
            || (bool)$row['is_ai_agent'] || !in_array($scope, explode(' ', $row['scopes']), true)) {
            return null;
        }
        if ($row['last_used_at'] === null || $row['last_used_at'] <= $this->utc(-60)) {
            $this->pdo->prepare('UPDATE api_tokens SET last_used_at = ? WHERE id = ?')->execute([$now, $row['token_id']]);
        }
        return ['id' => (int)$row['id'], 'username' => $row['username'], 'role' => $row['role'],
                'token_id' => (int)$row['token_id'], 'token_name' => $row['token_name']];
    }

    private function utc(int $offsetSeconds = 0): string
    {
        return gmdate('Y-m-d H:i:s', time() + $offsetSeconds);
    }

    public function logout(): void
    {
        $this->sessionStart();
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $p = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
        }
        session_destroy();
    }
}
