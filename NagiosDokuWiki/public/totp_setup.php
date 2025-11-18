<?php
$config = require __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/totp.php';
require_once __DIR__ . '/../includes/auth.php';

start_secure_session($config);
send_security_headers();

$pdo = db($config);

// Vérifie que l'utilisateur a une session pending_uid
if (!isset($_SESSION['pending_uid'])) {
    header('Location: login.php');
    exit;
}

$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$_SESSION['pending_uid']]);
$user = $stmt->fetch();

// Vérifie que l'utilisateur est bien admin ou superadmin
if (!$user || !in_array($user['role'], ['admin','superadmin'], true)) {
    die('Accès refusé');
}

// --- Gestion du secret TOTP temporaire ---
if (!$user['totp_secret'] || (int)$user['totp_enabled'] === 0) {
    if (!isset($_SESSION['pending_totp_secret'])) {
        $_SESSION['pending_totp_secret'] = totp_random_secret();
    }
    $secret = $_SESSION['pending_totp_secret'];
} else {
    $secret = $user['totp_secret'];
}

$uri = otpauth_uri($config['issuer'], $user['username'], $secret);
$msg = '';

// --- POST formulaire ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check($config);
    $code = trim($_POST['code'] ?? '');

    if (totp_verify($secret, $code)) {
        // Active TOTP et met à jour le timestamp
        $upd = $pdo->prepare('UPDATE users SET totp_secret=?, totp_enabled=1, updated_at=CURRENT_TIMESTAMP WHERE id=?');
        $upd->execute([$secret, $user['id']]);

        // Supprime les flags temporaires et active la session complète
        unset($_SESSION['pending_uid'], $_SESSION['pending_totp_secret']);
        $_SESSION['uid'] = $user['id'];

        log_event($config, $user['username'], 'totp_enabled', [
            'user_id' => $user['id']
        ]);

        header('Location: supervision.php');
        exit;
    } else {
        $msg = 'Code TOTP invalide, réessayez.';
    }
}
?>
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Configuration TOTP</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="css/styles.css">
<style>
body { font-family: system-ui, Segoe UI, Roboto, Arial; margin:2rem; background:#0b1020; color:#fff; }
.card { background:#1a1f30; padding:2rem; border-radius:.75rem; max-width:400px; margin:auto; box-shadow:0 0 15px rgba(0,0,0,.5); }
.badge.crit { background:#8b0000; color:#fff; padding:.5rem 1rem; border-radius:.5rem; margin-bottom:1rem; display:block; text-align:center; }
.kv div { margin:.2rem 0; }
</style>
</head>
<body>
<div class="card">
<h2>Activation obligatoire du TOTP</h2>

<?php if ($msg): ?>
<p class="badge crit"><?= e($msg) ?></p>
<?php endif; ?>

<p>Scanne ce QR code avec Google Authenticator / Aegis / Authy ou saisissez le secret manuellement.</p>

<div id="qrcode" style="margin: 1rem 0;"></div>

<div class="kv">
    <div>Secret : <code><?= e($secret) ?></code></div>
    <div>URI : <code style="word-break:break-all"><?= e($uri) ?></code></div>
</div>

<form method="post">
<?= csrf_field($config) ?>
<label>Entrez le code TOTP pour valider l’activation<br>
<input name="code" placeholder="123456" required>
</label>
<button class="btn primary" type="submit" style="margin-top:.5rem">Activer</button>
</form>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<script>
new QRCode(document.getElementById("qrcode"), {
    text: "<?= $uri ?>",
    width: 240,
    height: 240,
    correctLevel: QRCode.CorrectLevel.H
});
</script>
</body>
</html>