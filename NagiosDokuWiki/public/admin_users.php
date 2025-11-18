<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/totp.php';

$config = require __DIR__ . '/../config/config.php';
$pdo = db($config);

start_secure_session($config);
$user = current_user($pdo);

require_role($user, ['admin', 'superadmin']);

$messages = [];

// --- Vérification et ajout de la colonne must_change_password si nécessaire ---
try {
    $cols = $pdo->query("PRAGMA table_info(users)")->fetchAll(PDO::FETCH_ASSOC);
    $col_names = array_column($cols, 'name');
    if (!in_array('must_change_password', $col_names, true)) {
        $pdo->exec("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0");
    }
} catch (PDOException $e) {
    die("Erreur lors de la vérification de la colonne must_change_password : " . $e->getMessage());
}

// --- Fonction pour récupérer la date du dernier reset TOTP ---
function last_totp_reset(array $config, string $username): ?string {
    $file = $config['journal_path'] ?? __DIR__.'/../data/events.log';
    if (!file_exists($file)) return null;

    $last = null;
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $entry = json_decode($line, true);
        if (!$entry) continue;
        if ($entry['action']==='reset_totp' && isset($entry['ctx']['target_username']) && $entry['ctx']['target_username']===$username) {
            $last = $entry['ts'];
        }
    }
    return $last;
}

// --- Fonction pour générer un mot de passe aléatoire ---
function random_password($length = 12) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+';
    $password = '';
    for ($i=0; $i<$length; $i++) {
        $password .= $chars[random_int(0, strlen($chars)-1)];
    }
    return $password;
}

// --- Suppression utilisateur ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['del_user'])) {
    csrf_check($config);
    $uid = (int)$_POST['del_user'];

    try {
        $stmt = $pdo->prepare("SELECT username, role FROM users WHERE id=?");
        $stmt->execute([$uid]);
        $target = $stmt->fetch();

        if (!$target) {
            $messages[] = "Utilisateur introuvable pour ID $uid.";
        } elseif ($uid === (int)$user['id']) {
            $messages[] = "Vous ne pouvez pas supprimer votre propre compte.";
        } elseif ($target['role'] === 'superadmin' && $user['role'] !== 'superadmin') {
            $messages[] = "Vous ne pouvez pas supprimer un superadmin.";
        } else {
            $stmt = $pdo->prepare("DELETE FROM users WHERE id=?");
            $stmt->execute([$uid]);
            $messages[] = "Utilisateur " . htmlspecialchars($target['username']) . " supprimé.";

            log_event($config, $user['username'], 'delete_user', [
                'target_username' => $target['username'],
                'target_role' => $target['role'],
                'target_id' => $uid
            ]);
        }
    } catch (PDOException $e) {
        $messages[] = "Erreur SQL: " . $e->getMessage();
    }
}

// --- Réinitialisation TOTP ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reset_totp'], $_POST['uid'])) {
    csrf_check($config);
    $uid = (int)$_POST['uid'];
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id=?");
    $stmt->execute([$uid]);
    $target = $stmt->fetch();

    if ($target && in_array($target['role'], ['admin','superadmin'], true)) {
        $new_secret = totp_random_secret();
        $upd = $pdo->prepare("UPDATE users SET totp_secret=?, totp_enabled=0, updated_at=CURRENT_TIMESTAMP WHERE id=?");
        $upd->execute([$new_secret, $uid]);
        $messages[] = "TOTP réinitialisé pour " . htmlspecialchars($target['username']);

        log_event($config, $user['username'], 'reset_totp', [
            'target_username' => $target['username'],
            'target_role' => $target['role'],
            'target_id' => $uid
        ]);
    }
}

// --- Réinitialisation mot de passe avec obligation de changer ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reset_password'], $_POST['uid'])) {
    csrf_check($config);
    $uid = (int)$_POST['uid'];
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id=?");
    $stmt->execute([$uid]);
    $target = $stmt->fetch();

    if (!$target) {
        $messages[] = "Utilisateur introuvable.";
    } elseif ($target['role'] === 'superadmin' && $user['role'] !== 'superadmin') {
        $messages[] = "Vous ne pouvez pas réinitialiser le mot de passe d’un superadmin.";
    } else {
        $new_password = random_password(12);
        $upd = $pdo->prepare("UPDATE users SET password_hash=?, must_change_password=1, updated_at=CURRENT_TIMESTAMP WHERE id=?");
        $upd->execute([password_hash($new_password, PASSWORD_DEFAULT), $uid]);
        $messages[] = "Mot de passe réinitialisé pour " . htmlspecialchars($target['username']) . ". Nouveau mot de passe : <strong>" . htmlspecialchars($new_password) . "</strong>";

        log_event($config, $user['username'], 'reset_password', [
            'target_username' => $target['username'],
            'target_role' => $target['role'],
            'target_id' => $uid
        ]);
    }
}

// --- Création utilisateur ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'], $_POST['role'])) {
    csrf_check($config);
    $username = trim($_POST['username']);
    $role = $_POST['role'];
    $password_input = $_POST['password'] ?? '';
    $must_change = 1; // par défaut, nouvel utilisateur doit changer le mot de passe

    if ($role === 'superadmin' && $user['role'] !== 'superadmin') {
        $messages[] = "Seul un superadmin peut créer un superadmin.";
    } else {
        try {
            // Vérifie si le nom d'utilisateur existe déjà
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username=?");
            $stmt->execute([$username]);
            $existing = $stmt->fetch();

            if ($existing) {
                $messages[] = "Erreur : nom d'utilisateur déjà utilisé.";
            } else {
                // --- Création nouvel utilisateur ---
                if (!$password_input) {
                    $plain_password = random_password(12);
                    $password_hash = password_hash($plain_password, PASSWORD_DEFAULT);
                    $messages[] = "Mot de passe généré pour $username : <strong>$plain_password</strong>";
                } else {
                    $password_hash = password_hash($password_input, PASSWORD_DEFAULT);
                }

                // Gestion TOTP pour admins
                $totp_secret = null;
                $totp_enabled = 0;
                if (in_array($role, ['admin','superadmin'], true)) {
                    $totp_secret = totp_random_secret();
                }

                $stmt = $pdo->prepare(
                    "INSERT INTO users (username, password_hash, role, must_change_password, totp_secret, totp_enabled) 
                     VALUES (?, ?, ?, ?, ?, ?)"
                );
                $stmt->execute([$username, $password_hash, $role, $must_change, $totp_secret, $totp_enabled]);
                $newId = $pdo->lastInsertId();
                $messages[] = "Utilisateur créé avec succès.";
                log_event($config, $user['username'], 'create_user', [
                    'target_id' => $newId,
                    'username' => $username,
                    'role' => $role
                ]);
            }
        } catch (PDOException $e) {
            $messages[] = "Erreur SQL : " . $e->getMessage();
        }
    }
}

// --- Récupération utilisateurs ---
$users = $pdo->query("SELECT * FROM users ORDER BY id ASC")->fetchAll();

include __DIR__ . '/../includes/header.php';
?>

<h1 class="page-title">Gestion des utilisateurs</h1>

<?php if ($messages): ?>
<div class="messages">
    <?php foreach ($messages as $msg): ?>
        <div class="alert"><?= $msg ?></div>
    <?php endforeach; ?>
</div>
<?php endif; ?>

<div class="card">
<h2 style="font-size:1rem;">Ajouter un utilisateur</h2>
<form method="post">
    <?= csrf_field($config) ?>
    <input type="hidden" name="id" value="">
    <div class="form-group">
        <label>Nom d'utilisateur :</label>
        <input type="text" name="username" required>
    </div>
    <div class="form-group">
        <label>Mot de passe :</label>
        <input type="password" name="password">
    </div>
    <div class="form-group">
        <label>Rôle :</label>
        <select name="role">
            <option value="user">Utilisateur</option>
            <option value="admin">Admin</option>
            <?php if ($user['role']==='superadmin'): ?>
            <option value="superadmin">Superadmin</option>
            <?php endif; ?>
        </select>
    </div>
    <button type="submit" class="btn primary">Enregistrer</button>
</form>
</div>

<div class="card">
<h2 style="font-size:1rem;">Liste des utilisateurs</h2>
<table class="table">
<thead>
<tr>
<th>ID</th><th>Nom</th><th>Rôle</th><th>TOTP</th><th>Actions</th>
</tr>
</thead>
<tbody>
<?php foreach($users as $u):
    $roleClass = $u['role']==='superadmin'?'crit':($u['role']==='admin'?'warn':'ok');
    $totpEnabled = $u['totp_enabled'] == 1;
    $totpReset = null;
    $totpIsReset = false;

    if (in_array($u['role'], ['admin','superadmin'], true)) {
        $totpReset = last_totp_reset($config, $u['username']);
        if ($totpReset && !$totpEnabled) {
            $totpIsReset = true;
        }
    }

    $is_disabled = ($u['id'] === (int)$user['id'] || ($u['role'] === 'superadmin' && $user['role'] !== 'superadmin'));
    $totpButtonDisabled = $totpIsReset || $is_disabled;
    $resetPasswordDisabled = ($u['role']==='superadmin' && $user['role'] !== 'superadmin');
?>
<tr class="row-<?=$roleClass?>">
<td><?= $u['id'] ?></td>
<td><?= htmlspecialchars($u['username']) ?></td>
<td><span class="badge <?=$roleClass?>"><?= htmlspecialchars($u['role']) ?></span></td>
<td>
    <span class="badge <?= $totpEnabled ? 'ok' : 'unknown' ?>"><?= $totpEnabled ? 'Activé' : 'Inactif' ?></span>
    <?php if(in_array($u['role'], ['admin','superadmin'], true) && !$totpEnabled): ?>
    <span class="badge warn">TOTP non configuré</span>
    <?php elseif($totpIsReset): ?>
    <span class="badge warn">TOTP réinitialisé</span>
    <?php endif; ?>
</td>
<td>
<form method="post" class="del-user-form" style="display:inline">
<?= csrf_field($config) ?>
<input type="hidden" name="del_user" value="<?= $u['id'] ?>">
<button type="submit" class="btn del-user-btn"
    <?= $is_disabled ? 'disabled style="opacity:0.5;cursor:not-allowed;"' : '' ?>>
    Supprimer
</button>
</form>

<?php if(in_array($u['role'],['admin','superadmin'],true)): ?>
<form method="post" class="reset-totp-form" style="display:inline">
<?= csrf_field($config) ?>
<input type="hidden" name="uid" value="<?= $u['id'] ?>">
<button type="submit" name="reset_totp" class="btn reset-totp-btn"
    <?= $totpButtonDisabled ? 'disabled style="opacity:0.5;cursor:not-allowed;"' : '' ?>>
    Réinitialiser TOTP
</button>
</form>
<?php endif; ?>

<form method="post" class="reset-password-form" style="display:inline">
<?= csrf_field($config) ?>
<input type="hidden" name="uid" value="<?= $u['id'] ?>">
<button type="submit" name="reset_password" class="btn reset-password-btn"
    <?= $resetPasswordDisabled ? 'disabled style="opacity:0.5;cursor:not-allowed;"' : '' ?>>
    Réinitialiser mot de passe
</button>
</form>

</td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
</div>

<script>
document.querySelectorAll('.del-user-form').forEach(form => {
    form.addEventListener('submit', function(e){
        const btn = form.querySelector('.del-user-btn');
        if(btn.disabled) return;
        if(!confirm('Supprimer cet utilisateur ?')) e.preventDefault();
    });
});

document.querySelectorAll('.reset-totp-form').forEach(form => {
    form.addEventListener('submit', function(e){
        const btn = form.querySelector('.reset-totp-btn');
        if(btn.disabled) return;
        if(!confirm('Réinitialiser le TOTP pour cet utilisateur ?')) e.preventDefault();
    });
});

document.querySelectorAll('.reset-password-form').forEach(form => {
    form.addEventListener('submit', function(e){
        const btn = form.querySelector('.reset-password-btn');
        if(btn.disabled) return;
        if(!confirm('Réinitialiser le mot de passe pour cet utilisateur ?')) e.preventDefault();
    });
});
</script>

<?php include __DIR__ . '/../includes/footer.php'; ?>