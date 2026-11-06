<?php

declare(strict_types=1);

namespace Coder999\LoginKit\Tests;

use Coder999\LoginKit\Auth;
use PDO;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

final class AgentAccessTest extends TestCase
{
    private PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $this->pdo->exec('CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, last_login TEXT NULL,
            role TEXT NOT NULL DEFAULT \'user\', is_ai_agent INTEGER NOT NULL DEFAULT 0, agent_until TEXT NULL)');
        $this->pdo->exec('CREATE TABLE login_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, attempted_at TEXT NOT NULL)');
        $ins = $this->pdo->prepare('INSERT INTO users (id, username, password_hash, role, is_ai_agent) VALUES (?, ?, ?, ?, ?)');
        $ins->execute([1, 'boss@example.com', password_hash('boss-password', PASSWORD_DEFAULT), 'superadmin', 0]);
        $ins->execute([2, 'agent@example.com', password_hash('agent-password', PASSWORD_DEFAULT), 'superadmin', 1]);
        $ins->execute([3, 'user@example.com', password_hash('user-password', PASSWORD_DEFAULT), 'user', 0]);
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    }

    private function auth(bool $default = false): Auth
    {
        $auth = new Auth($this->pdo, ['agent_access_default' => $default]);
        $auth->sessionStart();
        $_SESSION = [];
        return $auth;
    }

    #[RunInSeparateProcess]
    public function testNeverSwitchedFollowsTheDefault(): void
    {
        $this->assertNull($this->auth()->agentAccessUntil());
        $this->assertSame('9999-12-31 23:59:59', $this->auth(true)->agentAccessUntil());
        $this->assertTrue($this->auth(true)->attemptLogin('agent@example.com', 'agent-password'));
    }

    #[RunInSeparateProcess]
    public function testOffRefusesTheRightPasswordWithAReasonAndNoFailure(): void
    {
        $auth = $this->auth();

        $this->assertFalse($auth->attemptLogin('agent@example.com', 'agent-password'));
        $this->assertSame(Auth::AGENT_ACCESS_OFF, $auth->lastRefusal());
        $this->assertArrayNotHasKey('user_id', $_SESSION);
        $this->assertSame(0, (int)$this->pdo->query('SELECT COUNT(*) FROM login_attempts')->fetchColumn());

        $this->assertFalse($auth->attemptLogin('agent@example.com', 'wrong'));
        $this->assertNull($auth->lastRefusal(), 'a wrong password reveals nothing');
        $this->assertTrue($auth->attemptLogin('user@example.com', 'user-password'));
        $this->assertNull($auth->lastRefusal());
    }

    #[RunInSeparateProcess]
    public function testSuperadminSwitchesOnThenOffWhichEndsTheAgentsSession(): void
    {
        $auth = $this->auth();
        $auth->loginAs(1);
        $this->assertTrue($auth->setAgentAccess(8));
        $until = $auth->agentAccessUntil();
        $this->assertNotNull($until);
        $this->assertEqualsWithDelta(time() + 8 * 3600, strtotime($until . ' UTC'), 5);

        $this->assertTrue($auth->attemptLogin('agent@example.com', 'agent-password'));
        $this->assertTrue($auth->currentUser()['is_ai_agent']);

        $this->pdo->exec("UPDATE users SET agent_until = '2000-01-01 00:00:00'");   // what setAgentAccess(0) leaves
        $this->assertNull($auth->currentUser(), 'the live agent session ends');
        $this->assertArrayNotHasKey('user_id', $_SESSION);
    }

    #[RunInSeparateProcess]
    public function testSwitchingOffBeatsTheDefault(): void
    {
        $auth = $this->auth(true);
        $auth->loginAs(1);
        $this->assertTrue($auth->setAgentAccess(0));

        $this->assertNull($auth->agentAccessUntil());
        $this->assertFalse($auth->attemptLogin('agent@example.com', 'agent-password'));
    }

    #[RunInSeparateProcess]
    public function testOnlyANonAgentSuperadminMaySwitch(): void
    {
        $auth = $this->auth(true);
        $this->assertFalse($auth->setAgentAccess(8), 'signed out');

        $auth->loginAs(3);
        $this->assertFalse($auth->setAgentAccess(8), 'not a superadmin');

        $auth->loginAs(2);
        $this->assertFalse($auth->setAgentAccess(8), 'an agent extending itself');
        $this->assertNull($this->pdo->query('SELECT MAX(agent_until) FROM users')->fetchColumn());
    }
}
