<?php
$config = require __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/totp.php';

start_secure_session($config);
send_security_headers();
$msg = '';

$pdo = db($config);

// --- Gestion du message session expirée ---
if (isset($_GET['expired']) && $_GET['expired'] == 1) {
    $msg = 'Votre session a expiré en raison de l’inactivité. Merci de vous reconnecter.';
}

// --- Base rate-limit ---
$rate_db_path = __DIR__ . '/../sqlite/rate.sqlite';
$rate_db = new PDO('sqlite:' . $rate_db_path);
$rate_db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

if (!file_exists($rate_db_path)) {
    $rate_db->exec("
        CREATE TABLE IF NOT EXISTS failed_logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip TEXT,
            ts INTEGER,
            reason TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_failed_logins_user_ip ON failed_logins(username, ip);
    ");
}

// --- IP et username pour rate-limit ---
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$username_input = trim($_POST['username'] ?? '');

// Vérifie les tentatives récentes
$window = time() - (15 * 60); // 15 min
$stmt = $rate_db->prepare("SELECT COUNT(*) FROM failed_logins WHERE username=? AND ip=? AND ts>=?");
$stmt->execute([$username_input, $ip, $window]);
$fail_count = (int)$stmt->fetchColumn();

if ($fail_count >= 5) {
    $msg = "Trop de tentatives. Réessaie dans quelques minutes.";
}

// --- POST login ---
if (!$msg && $_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check($config);

    $password   = $_POST['password'] ?? '';
    $totp_code  = trim($_POST['totp'] ?? '');
    $fail_reason = null;

    $stmt = $pdo->prepare('SELECT * FROM users WHERE username = ?');
    $stmt->execute([$username_input]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password_hash'])) {
        // Reset tentatives
        $stmt = $rate_db->prepare("DELETE FROM failed_logins WHERE username=? AND ip=?");
        $stmt->execute([$username_input, $ip]);

        // --- Forcer changement mot de passe si demandé ---
        if ((int)$user['must_change_password'] === 1) {
            $_SESSION['force_change_uid'] = $user['id'];
            unset($_SESSION['uid']);
            header('Location: force_change_password.php');
            exit;
        }

        // --- Gestion TOTP pour admins ---
        if (in_array($user['role'], ['admin','superadmin'], true)) {
            if ((int)$user['totp_enabled'] === 0 || !$user['totp_secret']) {
                // Force la configuration TOTP
                $_SESSION['pending_uid'] = $user['id'];
                unset($_SESSION['uid']);
                header('Location: totp_setup.php');
                exit;
            } else {
                if (!$totp_code) {
                    $msg = 'Code TOTP requis';
                    $fail_reason = 'TOTP manquant';
                } elseif (!totp_verify($user['totp_secret'], $totp_code, 30, 6, 1)) {
                    $msg = 'Code TOTP invalide';
                    $fail_reason = 'TOTP invalide';
                } else {
                    $_SESSION['uid'] = $user['id'];
                }
            }
        } else {
            $_SESSION['uid'] = $user['id'];
        }

    } else {
        $msg = 'Identifiants invalides';
        $fail_reason = $user ? 'Mot de passe invalide' : 'Utilisateur inexistant';
    }

    // --- Logs tentatives ratées ---
    if ($fail_reason) {
        $stmt = $rate_db->prepare("INSERT INTO failed_logins (username, ip, ts, reason) VALUES (?, ?, ?, ?)");
        $stmt->execute([$username_input, $ip, time(), $fail_reason]);

        log_event($config, $username_input ?: null, 'login_failed', [
            'ip' => $ip,
            'reason' => $fail_reason,
            'timestamp' => time()
        ]);
    }

    // --- Login réussi ---
    if (isset($_SESSION['uid'])) {
        log_event($config, $user['username'] ?? null, 'login', ['role'=>$user['role'] ?? null]);
        header('Location: supervision.php');
        exit;
    }
}

// Purge anciens logs
$rate_db->exec("DELETE FROM failed_logins WHERE ts < " . (time() - 30*24*3600));

$show_init_msg = !file_exists(__DIR__ . '/../sqlite/supervision.sqlite');
?>
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Connexion – Supervision DokuWiki</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="css/styles.css">
<style>
.login-wrapper { display:flex; justify-content:center; align-items:center; height:100vh; }
.login-card { background: var(--card); padding:2rem; border-radius:0.75rem; width:100%; max-width:400px; box-shadow:0 0 15px rgba(0,0,0,0.4); }
.login-card h2 { text-align:center; margin-bottom:1.5rem; }
.form-group { margin-bottom:1rem; display:flex; flex-direction:column; }
.form-group label { margin-bottom:0.25rem; font-weight:500; }
.form-group input { padding:0.5rem; border-radius:0.4rem; border:1px solid rgba(255,255,255,0.1); background:#0b1020; color:var(--text); }
.btn.primary { width:100%; margin-top:0.5rem; }
.badge.crit { background:#8b0000; color:#fff; padding:0.5rem 1rem; border-radius:0.5rem; }
</style>
</head>
<body>
<div class="login-wrapper">
  <div class="login-card">
    <h2>Supervision DokuWiki</h2>

    <?php if ($msg): ?>
      <p class="badge crit" style="text-align:center;margin-bottom:1rem"><?=e($msg)?></p>
    <?php endif; ?>

    <form method="post">
      <?=csrf_field($config)?>

      <div class="form-group">
        <label for="username">Identifiant</label>
        <input id="username" name="username" required autofocus value="<?=htmlspecialchars($username_input)?>">
      </div>

      <div class="form-group">
        <label for="password">Mot de passe</label>
        <input id="password" type="password" name="password" required>
      </div>

      <div class="form-group">
        <label for="totp">Code TOTP (si requis)</label>
        <input id="totp" name="totp" placeholder="123456">
      </div>

      <button class="btn primary" type="submit">Se connecter</button>
    </form>

    <?php if ($show_init_msg): ?>
      <p class="muted" style="text-align:center;margin-top:1rem;">
        Première utilisation ? Lance <code>config/init_db.php</code> pour créer le superadmin.
      </p>
    <?php endif; ?>
  </div>
</div>
</body>
</html>