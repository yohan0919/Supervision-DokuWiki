<?php
// includes/auth.php

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/totp.php';

/**
 * Démarre une session sécurisée avec gestion de l'inactivité
 */
function start_secure_session(array $config): void {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_name($config['session_name']);
        session_set_cookie_params([
            'lifetime' => $config['session_cookie_life'],
            'path' => '/',
            'httponly' => true,
            'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
            'samesite' => 'Lax',
        ]);
        session_start();
    }

    // --- Gestion de l'inactivité ---
    $timeout = $config['session_inactivity_timeout'] ?? 1800; // 30 min par défaut
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $timeout) {
        // Session expirée → déconnexion
        $_SESSION = [];
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        session_destroy();
        header("Location: login.php?expired=1");
        exit;
    }

    // Mise à jour du timestamp d'activité
    $_SESSION['last_activity'] = time();
}

/**
 * Récupère l'utilisateur courant depuis la session
 */
function current_user(PDO $pdo): ?array {
    if (!isset($_SESSION['uid'])) return null;
    $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([$_SESSION['uid']]);
    return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}

/**
 * Vérifie qu'un utilisateur est connecté, sinon redirige vers login
 */
function require_login(array $config, PDO $pdo): array {
    start_secure_session($config);
    $u = current_user($pdo);
    if (!$u) {
        header('Location: login.php');
        exit;
    }
    return $u;
}

/**
 * Vérifie que l'utilisateur a le rôle requis
 * @param ?array $user L'utilisateur courant
 * @param array $roles Liste des rôles autorisés
 */
function require_role(?array $user, array $roles): void {
    if (!$user || !isset($user['role']) || !in_array($user['role'], $roles, true)) {
        http_response_code(403);
        die('Accès refusé');
    }
}

/**
 * Déconnecte l'utilisateur courant
 */
function logout(array $config): void {
    start_secure_session($config);
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    session_destroy();
}