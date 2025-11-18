<?php
// includes/header.php
// Header commun — appelle start_secure_session & en-têtes de sécurité
if (!isset($config)) {
    // si inclus depuis une page publique, charger config si nécessaire
    $config = require __DIR__ . '/../config/config.php';
}
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';

start_secure_session($config);
send_security_headers();

// Récupère l'utilisateur courant si possible
$pdo = db($config);
$user = null;
if (isset($_SESSION['uid'])) {
    $user = current_user($pdo);
}

// helper pour afficher les liens selon rôle
function nav_link($href, $label) {
    return '<a class="nav-link" href="' . htmlspecialchars($href) . '">' . htmlspecialchars($label) . '</a>';
}
?>
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>Supervision DokuWiki</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link rel="stylesheet" href="css/styles.css">
</head>
<body>
<header class="topbar">
  <div class="brand">
    <strong>Supervision</strong> <span class="muted">DokuWiki</span>
  </div>

  <nav class="nav">
    <?= nav_link('supervision.php', 'État') ?>
    <?php if ($user && in_array($user['role'], ['admin','superadmin'], true)): ?>
      <?= nav_link('admin_users.php', 'Utilisateurs') ?>
      <?= nav_link('journal.php', 'Journal') ?>
    <?php endif; ?>
  </nav>

  <div class="userbox">
    <?php if ($user): ?>
      <span class="user"><?=htmlspecialchars($user['username'])?> (<?=htmlspecialchars($user['role'])?>)</span>
      <a class="btn" href="logout.php">Se déconnecter</a>
    <?php else: ?>
      <a class="btn" href="login.php">Se connecter</a>
    <?php endif; ?>
  </div>
</header>

<main class="container">
  <section class="content">
