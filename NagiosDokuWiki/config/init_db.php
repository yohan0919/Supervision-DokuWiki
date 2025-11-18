<?php
// config/init_db.php
// Script d’initialisation à lancer UNE SEULE FOIS pour créer la base et le premier superadmin.

$config = require __DIR__ . '/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/functions.php';

$pdo = db($config);

// Création de la table users si elle n’existe pas déjà
$pdo->exec('CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ("superadmin","admin","user")),
    totp_secret TEXT DEFAULT NULL,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)');

// Vérifie si des utilisateurs existent déjà
$exists = (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
if ($exists > 0) {
    http_response_code(403);
    echo 'Base déjà initialisée.';
    exit;
}

// Si formulaire soumis
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = trim($_POST['username'] ?? '');
    $p = $_POST['password'] ?? '';

    if ($u !== '' && $p !== '') {
        $stmt = $pdo->prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, "superadmin")');
        try {
            $stmt->execute([$u, password_hash($p, PASSWORD_DEFAULT)]);
            echo '<p>Superadmin créé avec succès. Supprimez <code>init_db.php</code> ou rendez-le inaccessible.</p>';
            exit;
        } catch (Throwable $e) {
            echo '<p>Erreur : ' . e($e->getMessage()) . '</p>';
        }
    } else {
        echo '<p>Veuillez fournir un identifiant et un mot de passe.</p>';
    }
}
?>
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>Init DB – Supervision</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
      body { font-family: system-ui, Segoe UI, Roboto, Arial; margin: 2rem }
      form { max-width: 420px }
      label { display: block; margin: .5rem 0 }
      .box { border: 1px solid #ddd; padding: 1rem; border-radius: 8px }
  </style>
</head>
<body>
  <h1>Initialisation de la base</h1>
  <p class="box">
    Crée le <strong>premier superadmin</strong>.  
    Ensuite, supprimez ce fichier <code>init_db.php</code> ou protégez-le.
  </p>
  <form method="post">
    <label>Identifiant
      <input name="username" required>
    </label>
    <label>Mot de passe
      <input type="password" name="password" required>
    </label>
    <button type="submit">Créer le superadmin</button>
  </form>
</body>
</html>