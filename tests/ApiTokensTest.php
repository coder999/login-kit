<?php

declare(strict_types=1);

namespace Coder999\LoginKit\Tests;

use Coder999\LoginKit\Auth;
use PDO;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

final class ApiTokensTest extends TestCase
{
    private PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $this->pdo->exec('CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
            password_hash TEXT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, last_login TEXT NULL,
            role TEXT NOT NULL DEFAULT \'user\', is_ai_agent INTEGER NOT NULL DEFAULT 0, agent_until TEXT NULL)');
        $this->pdo->exec('CREATE TABLE login_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, attempted_at TEXT NOT NULL)');
        $this->pdo->exec('CREATE TABLE api_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE, scopes TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NULL,
            last_used_at TEXT NULL, revoked_at TEXT NULL)');
        $ins = $this->pdo->prepare('INSERT INTO users (id, username, role, is_ai_agent, agent_until) VALUES (?, ?, ?, ?, ?)');
        $ins->execute([1, 'boss@example.com', 'superadmin', 0, null]);
        $ins->execute([2, 'agent@example.com', 'superadmin', 1, gmdate('Y-m-d H:i:s', time() + 3600)]);   // access on
        $ins->execute([3, 'user@example.com', 'user', 0, null]);
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    }

    private function as(int $userId): Auth
    {
        $auth = new Auth($this->pdo);
        $auth->sessionStart();
        $_SESSION = [];
        $auth->loginAs($userId);
        return $auth;
    }

    #[RunInSeparateProcess]
    public function testIssuedTokenIsStoredOnlyAsItsHashAndWorksOnlyForItsScopes(): void
    {
        $auth = $this->as(1);
        $token = $auth->issueApiToken('Rack kiosk', ['admin:wall', 'admin:wall']);

        $this->assertMatchesRegularExpression('/^lkt_[0-9a-f]{64}$/', $token);
        $this->assertSame(hash('sha256', $token), $this->pdo->query('SELECT token_hash FROM api_tokens')->fetchColumn());
        $this->assertSame('admin:wall', $this->pdo->query('SELECT scopes FROM api_tokens')->fetchColumn(), 'scopes de-duplicated');

        $who = $auth->apiTokenUser($token, 'admin:wall');
        $this->assertSame(['id' => 1, 'username' => 'boss@example.com', 'role' => 'superadmin', 'token_id' => 1, 'token_name' => 'Rack kiosk'], $who);
        $this->assertNotNull($this->pdo->query('SELECT last_used_at FROM api_tokens')->fetchColumn());
        $this->assertNull($auth->apiTokenUser($token, 'admin:accounts'), 'only its own scopes');
        $this->assertNull($auth->apiTokenUser(substr($token, 0, -1) . 'x', 'admin:wall'), 'malformed');
        $this->assertNull($auth->apiTokenUser('lkt_' . str_repeat('0', 64), 'admin:wall'), 'unknown');
        $this->assertNull($auth->apiTokenUser(substr($token, 4), 'admin:wall'), 'the prefix is part of it');
    }

    #[RunInSeparateProcess]
    public function testListShowsNoSecretsAndRevokeIsTheOwnersAlone(): void
    {
        $auth = $this->as(1);
        $first = $auth->issueApiToken('First', ['admin:wall'], 30);
        $auth->issueApiToken('Second', ['admin:wall', 'x:y']);
        $list = $auth->apiTokens();

        $this->assertSame(['Second', 'First'], array_column($list, 'name'), 'newest first');
        $this->assertSame(['admin:wall', 'x:y'], $list[0]['scopes']);
        $this->assertNull($list[0]['expires_at']);
        $this->assertEqualsWithDelta(time() + 30 * 86400, strtotime($list[1]['expires_at'] . ' UTC'), 5);
        $this->assertArrayNotHasKey('token_hash', $list[0]);

        $user = $this->as(3);
        $this->assertSame([], $user->apiTokens(), 'only your own');
        $this->assertFalse($user->revokeApiToken($list[1]['id']), "not someone else's");

        $auth = $this->as(1);
        $this->assertTrue($auth->revokeApiToken($list[1]['id']));
        $this->assertFalse($auth->revokeApiToken($list[1]['id']), 'already revoked');
        $this->assertNull($auth->apiTokenUser($first, 'admin:wall'), 'revoked takes effect at once');
        $this->assertNotNull($auth->apiTokens()[1]['revoked_at']);
    }

    #[RunInSeparateProcess]
    public function testExpiredTokensAndAgentOwnersAreRefused(): void
    {
        $auth = $this->as(1);
        $token = $auth->issueApiToken('Short', ['admin:wall'], 1);
        $this->pdo->exec("UPDATE api_tokens SET expires_at = '2000-01-01 00:00:00'");
        $this->assertNull($auth->apiTokenUser($token, 'admin:wall'));

        $token = $auth->issueApiToken('Owner turns agent', ['admin:wall']);
        $this->pdo->exec('UPDATE users SET is_ai_agent = 1 WHERE id = 1');
        $this->assertNull($auth->apiTokenUser($token, 'admin:wall'), 'an agent account never speaks through a token');
    }

    #[RunInSeparateProcess]
    public function testAnAgentMayNotMintOrRevokeAndNoOneSignedInGetsNothing(): void
    {
        $agent = $this->as(2);
        $this->assertTrue($agent->currentUser()['is_ai_agent'], 'signed in while access is on');
        $this->assertNull($agent->issueApiToken('Mine', ['admin:wall']));
        $this->assertFalse($agent->revokeApiToken(1));
        $this->assertSame(0, (int)$this->pdo->query('SELECT COUNT(*) FROM api_tokens')->fetchColumn());

        $auth = new Auth($this->pdo);
        $auth->sessionStart();
        $_SESSION = [];
        $this->assertNull($auth->issueApiToken('Nobody', ['admin:wall']));
        $this->assertSame([], $auth->apiTokens());
    }

    #[RunInSeparateProcess]
    public function testBadNamesScopesAndTtlsThrow(): void
    {
        $auth = $this->as(1);
        foreach ([['', ['a']], [str_repeat('n', 81), ['a']], ['ok', []], ['ok', ['Admin:Wall']], ['ok', ['a b']], ['ok', [str_repeat('a', 41)]]] as [$name, $scopes]) {
            try {
                $auth->issueApiToken($name, $scopes);
                $this->fail('accepted ' . json_encode([$name, $scopes]));
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
        $this->expectException(\InvalidArgumentException::class);
        $auth->issueApiToken('ok', ['a'], 0);
    }
}
