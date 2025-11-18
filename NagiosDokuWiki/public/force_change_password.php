<?php
// force_change_password.php
$config = require __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/totp.php';

start_secure_session($config);
send_security_headers();
$pdo = db($config);
$msg = '';

// --- Récupération de l'utilisateur ---
$user = current_user($pdo);

// Si non connecté, tente de récupérer via force_change_uid
if (!$user && isset($_SESSION['force_change_uid'])) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id=?");
    $stmt->execute([$_SESSION['force_change_uid']]);
    $user = $stmt->fetch();
}

// Si aucun utilisateur valide → retour login
if (!$user) {
    header('Location: login.php');
    exit;
}

// Vérifie si l'utilisateur doit changer son mot de passe
if ((int)$user['must_change_password'] !== 1) {
    // Pour les admins sans TOTP configuré, force la configuration
    if (in_array($user['role'], ['admin','superadmin'], true) && ((int)$user['totp_enabled'] === 0 || !$user['totp_secret'])) {
        $_SESSION['pending_uid'] = $user['id'];
        unset($_SESSION['uid']);
        header('Location: totp_setup.php');
        exit;
    }
    header('Location: supervision.php');
    exit;
}

// --- POST formulaire ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check($config);

    $old_password = $_POST['old_password'] ?? '';
    $new_password = $_POST['new_password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    // Vérifie le mot de passe actuel
    if (!password_verify($old_password, $user['password_hash'])) {
        $msg = "Mot de passe actuel incorrect.";
    } 
    // Vérifie que les deux champs correspondent
    elseif ($new_password !== $confirm_password) {
        $msg = "Les nouveaux mots de passe ne correspondent pas.";
    } 
    // Vérifie la robustesse du mot de passe
    elseif (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$/', $new_password)) {
        $msg = "Le mot de passe doit faire au moins 12 caractères, contenir une majuscule, une minuscule, un chiffre et un caractère spécial.";
    } else {
        // Met à jour le mot de passe et supprime le flag must_change_password
        $stmt = $pdo->prepare("UPDATE users SET password_hash=?, must_change_password=0, updated_at=CURRENT_TIMESTAMP WHERE id=?");
        $stmt->execute([password_hash($new_password, PASSWORD_DEFAULT), $user['id']]);

        log_event($config, $user['username'], 'force_password_change', [
            'user_id' => $user['id']
        ]);

        // --- Gestion TOTP post changement ---
        if (in_array($user['role'], ['admin','superadmin'], true) && ((int)$user['totp_enabled'] === 0 || !$user['totp_secret'])) {
            $_SESSION['pending_uid'] = $user['id'];
            unset($_SESSION['uid']);
            unset($_SESSION['force_change_uid']);
            header('Location: totp_setup.php');
            exit;
        }

        // Reconnexion de l'utilisateur
        $_SESSION['uid'] = $user['id'];
        unset($_SESSION['force_change_uid']); // plus nécessaire
        header('Location: supervision.php');
        exit;
    }
}
?>
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Changer votre mot de passe – Supervision</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="css/styles.css">
<style>
body { font-family: system-ui, Segoe UI, Roboto, Arial; margin: 2rem; background:#0b1020; color:#fff; }
.card { background: #1a1f30; padding:2rem; border-radius:0.75rem; max-width:400px; margin:auto; box-shadow:0 0 15px rgba(0,0,0,0.5); }
h2 { text-align:center; margin-bottom:1.5rem; }
.form-group { margin-bottom:1rem; display:flex; flex-direction:column; }
.form-group label { margin-bottom:0.25rem; font-weight:500; }
.form-group input { padding:0.5rem; border-radius:0.4rem; border:1px solid rgba(255,255,255,0.1); background:#0b1020; color:#fff; }
.btn.primary { width:100%; margin-top:0.5rem; }
.badge.crit { background:#8b0000; color:#fff; padding:0.5rem 1rem; border-radius:0.5rem; margin-bottom:1rem; display:block; text-align:center; }
</style>
</head>
<body>
<div class="card">
<h2>Changement obligatoire de mot de passe</h2>

<?php if ($msg): ?>
<p class="badge crit"><?= htmlspecialchars($msg) ?></p>
<?php endif; ?>

<form method="post">
<?= csrf_field($config) ?>

<div class="form-group">
    <label for="old_password">Mot de passe actuel</label>
    <input id="old_password" type="password" name="old_password" required autofocus>
</div>

<div class="form-group">
    <label for="new_password">Nouveau mot de passe</label>
    <input id="new_password" type="password" name="new_password" required>
</div>

<div class="form-group">
    <label for="confirm_password">Confirmer le nouveau mot de passe</label>
    <input id="confirm_password" type="password" name="confirm_password" required>
</div>

<button class="btn primary" type="submit">Valider</button>
</form>
</div>
</body>
</html>