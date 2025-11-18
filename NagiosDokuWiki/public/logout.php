<?php
// public/logout.php
$config = require __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/auth.php';

start_secure_session($config);
$pdo = db($config);

// journalise si possible
$username = null;
if (isset($_SESSION['uid'])) {
    $stmt = $pdo->prepare('SELECT username FROM users WHERE id = ?');
    $stmt->execute([$_SESSION['uid']]);
    $row = $stmt->fetch();
    $username = $row['username'] ?? null;
}

log_event($config, $username, 'logout');

$_SESSION = [];
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}
session_destroy();

header('Location: login.php');
exit;