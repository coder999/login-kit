<?php

declare(strict_types=1);

namespace Coder999\LoginKit;

use PDO;

final class Auth
{
    /** The role that passes every hasRole() check. */
    public const SUPERADMIN = 'superadmin';

    private PDO $pdo;
    private string $cookieName;
    private string $cookieDomain;
    private bool $cookieSecure;
    private int $loginMaxAttempts;
    private int $loginWindowSeconds;

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
        session_set_cookie_params([
            'lifetime' => 0,
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
        $st = $this->pdo->prepare('SELECT id, username, role, last_login FROM users WHERE id = ?');
        $st->execute([$_SESSION['user_id']]);
        $user = $st->fetch(PDO::FETCH_ASSOC);
        if ($user === false) {
            return null;
        }
        $user['id'] = (int)$user['id'];
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
        $st = $this->pdo->prepare('SELECT * FROM users WHERE username = ?');
        $st->execute([$username]);
        $user = $st->fetch(PDO::FETCH_ASSOC);

        if ($user !== false && password_verify($password, $user['password_hash'])) {
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
        $st = $this->pdo->prepare('SELECT id FROM users WHERE id = ?');
        $st->execute([$userId]);
        if ($st->fetch(PDO::FETCH_ASSOC) === false) {
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
        $token = bin2hex(random_bytes(32));
        $this->pdo->prepare('INSERT INTO password_resets (user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)')
            ->execute([$user['id'], hash('sha256', $token), $now->format('Y-m-d H:i:s'),
                       $now->modify('+1 hour')->format('Y-m-d H:i:s')]);
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
