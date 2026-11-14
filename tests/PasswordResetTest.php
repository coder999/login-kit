<?php

declare(strict_types=1);

namespace Coder999\LoginKit\Tests;

use Coder999\LoginKit\Auth;
use PDO;
use PHPUnit\Framework\TestCase;

final class PasswordResetTest extends TestCase
{
    private PDO $pdo;
    private Auth $auth;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $this->pdo->exec('CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, last_login TEXT NULL,
            role TEXT NOT NULL DEFAULT \'user\', is_ai_agent INTEGER NOT NULL DEFAULT 0, agent_until TEXT NULL)');
        $this->pdo->exec('CREATE TABLE login_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, attempted_at TEXT NOT NULL)');
        $this->pdo->exec('CREATE TABLE sessions (id TEXT PRIMARY KEY, data TEXT NOT NULL, last_activity TEXT NOT NULL)');
        $this->pdo->exec('CREATE TABLE password_resets (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT NULL)');
        $this->pdo->prepare('INSERT INTO users (id, username, password_hash) VALUES (1, ?, ?), (15, ?, ?)')
            ->execute(['alice@example.com', password_hash('old-password', PASSWORD_DEFAULT),
                       'bob@example.com', password_hash('bobs-password', PASSWORD_DEFAULT)]);
        $this->auth = new Auth($this->pdo);
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    }

    private function rows(string $sql): int
    {
        return (int)$this->pdo->query($sql)->fetchColumn();
    }

    public function testUnknownAccountGetsNoTokenButSpendsTheBudget(): void
    {
        $this->assertNull($this->auth->requestPasswordReset('nobody@example.com'));
        $this->assertSame(1, $this->rows('SELECT COUNT(*) FROM login_attempts'));
        $this->assertSame(0, $this->rows('SELECT COUNT(*) FROM password_resets'));
    }

    public function testTokenIsStoredOnlyAsItsHash(): void
    {
        $token = $this->auth->requestPasswordReset('alice@example.com');

        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $token);
        $this->assertSame(hash('sha256', $token), $this->pdo->query('SELECT token_hash FROM password_resets')->fetchColumn());
        $this->assertSame(1, $this->auth->passwordResetUser($token));
        $this->assertNull($this->auth->passwordResetUser(str_repeat('0', 64)));
    }

    public function testResetSetsThePasswordAndSpendsEveryToken(): void
    {
        $first = $this->auth->requestPasswordReset('alice@example.com');
        $second = $this->auth->requestPasswordReset('alice@example.com');

        $this->assertTrue($this->auth->resetPassword($second, 'a-new-password'));

        $hash = $this->pdo->query('SELECT password_hash FROM users WHERE id = 1')->fetchColumn();
        $this->assertTrue(password_verify('a-new-password', $hash));
        $this->assertFalse($this->auth->resetPassword($second, 'again'), 'a token works once');
        $this->assertNull($this->auth->passwordResetUser($first), 'the older token is spent too');
        $this->assertTrue($this->auth->attemptLogin('alice@example.com', 'a-new-password'));
    }

    public function testExpiredTokenIsRefused(): void
    {
        $token = $this->auth->requestPasswordReset('alice@example.com');
        $this->pdo->exec("UPDATE password_resets SET expires_at = '2000-01-01 00:00:00'");

        $this->assertNull($this->auth->passwordResetUser($token));
        $this->assertFalse($this->auth->resetPassword($token, 'a-new-password'));
    }

    public function testThreeTokensAnHourPerAccount(): void
    {
        for ($i = 0; $i < 3; $i++) {
            $_SERVER['REMOTE_ADDR'] = "10.0.0.$i";   // different addresses, same account
            $this->assertNotNull($this->auth->requestPasswordReset('alice@example.com'));
        }
        $_SERVER['REMOTE_ADDR'] = '10.0.0.9';
        $this->assertNull($this->auth->requestPasswordReset('alice@example.com'));
    }

    public function testThrottledAddressGetsNoToken(): void
    {
        for ($i = 0; $i < 8; $i++) {
            $this->auth->noteLoginFailure();
        }
        $this->assertNull($this->auth->requestPasswordReset('alice@example.com'));
    }

    public function testResetEndsOnlyThatAccountsSessions(): void
    {
        $ins = $this->pdo->prepare("INSERT INTO sessions (id, data, last_activity) VALUES (?, ?, '2026-01-01 00:00:00')");
        $ins->execute(['alice-first', 'user_id|i:1;']);
        $ins->execute(['alice-later', 'csrf|s:4:"abcd";user_id|i:1;']);
        $ins->execute(['bob', 'user_id|i:15;']);
        $ins->execute(['other-key', 'admin_user_id|i:1;']);
        $ins->execute(['signed-out', 'csrf|s:4:"abcd";']);

        $this->assertTrue($this->auth->resetPassword($this->auth->requestPasswordReset('alice@example.com'), 'a-new-password'));

        $left = $this->pdo->query('SELECT id FROM sessions ORDER BY id')->fetchAll(PDO::FETCH_COLUMN);
        $this->assertSame(['bob', 'other-key', 'signed-out'], $left);
    }

    public function testInviteTokenLastsItsTtlSpendsNoBudgetAndFinishesLikeAReset(): void
    {
        $token = $this->auth->issueSetPasswordToken(15, 168);

        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $token);
        $this->assertSame(hash('sha256', $token), $this->pdo->query('SELECT token_hash FROM password_resets')->fetchColumn());
        $this->assertSame(0, $this->rows('SELECT COUNT(*) FROM login_attempts'));
        $row = $this->pdo->query('SELECT created_at, expires_at FROM password_resets')->fetch();
        $this->assertSame(168 * 3600, strtotime($row['expires_at']) - strtotime($row['created_at']));

        $this->assertSame(15, $this->auth->passwordResetUser($token));
        $this->assertTrue($this->auth->resetPassword($token, 'a-new-password'));
        $this->assertTrue($this->auth->attemptLogin('bob@example.com', 'a-new-password'));
        $this->assertNull($this->auth->passwordResetUser($token));
    }

    public function testInviteTokenIsRefusedForAnUnknownUserOrABadTtl(): void
    {
        foreach ([[999, 24], [15, 0], [15, 721]] as [$user, $hours]) {
            try {
                $this->auth->issueSetPasswordToken($user, $hours);
                $this->fail("issued a token for user $user, $hours hours");
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
        $this->assertSame(0, $this->rows('SELECT COUNT(*) FROM password_resets'));
    }

    public function testInviteTokenThatHasExpiredIsDead(): void
    {
        $token = $this->auth->issueSetPasswordToken(15, 1);
        $this->pdo->exec("UPDATE password_resets SET expires_at = '2000-01-01 00:00:00'");
        $this->assertNull($this->auth->passwordResetUser($token));
        $this->assertFalse($this->auth->resetPassword($token, 'a-new-password'));
    }
}
