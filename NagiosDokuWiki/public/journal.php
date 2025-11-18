<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/db.php';

$config = require __DIR__ . '/../config/config.php';
$pdo = db($config);

start_secure_session($config);
$user = current_user($pdo);
require_role($user, ['admin', 'superadmin']);

$logFile = __DIR__ . '/../logs/journal.log';

$perPage = 10;
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$filterAction = $_GET['action'] ?? '';

include __DIR__ . '/../includes/header.php';
?>

<h1 class="page-title">Journal</h1>

<div class="card shadow-lg">
    <!-- Barre d’outils -->
    <div class="toolbar">
        <form method="get" class="filter-form">
            <label for="action">Filtrer par action :</label>
            <select name="action" id="action">
                <option value="">Toutes</option>
                <option value="login" <?= $filterAction==='login'?'selected':''; ?>>Login</option>
                <option value="logout" <?= $filterAction==='logout'?'selected':''; ?>>Logout</option>
                <option value="create_user" <?= $filterAction==='create_user'?'selected':''; ?>>Create</option>
                <option value="delete_user" <?= $filterAction==='delete_user'?'selected':''; ?>>Delete</option>
                <option value="totp_reset" <?= $filterAction==='totp_reset'?'selected':''; ?>>TOTP Reset</option>
            </select>
            <button type="submit" class="btn btn-secondary">Filtrer</button>
        </form>
        <a href="export_logs.php" class="btn btn-primary">Exporter CSV</a>
    </div>

    <div class="table-container">
        <table class="table table-striped table-hover">
            <thead>
                <tr>
                    <th>Date / Heure</th>
                    <th>IP</th>
                    <th>Utilisateur</th>
                    <th>Action</th>
                    <th>Contexte</th>
                    <th>Agent utilisateur</th>
                    <th>Statut</th>
                </tr>
            </thead>
            <tbody>
                <?php
                if (file_exists($logFile)) {
                    $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                    $totalLines = count($lines);
                    $totalPages = ceil($totalLines / $perPage);
                    $offset = ($page - 1) * $perPage;
                    $lines = array_slice($lines, $offset, $perPage);

                    foreach ($lines as $line) {

                        $dt = new DateTime('now', new DateTimeZone('Europe/Paris'));
                        $entry = json_decode($line, true);
                        if (!$entry) continue;

                        $ts = $entry['ts'] ?? '';
                        $ip = $entry['ip'] ?? '';
                        $username = $entry['user'] ?? '';
                        $action = $entry['action'] ?? '';
                        $ctx = isset($entry['ctx']) && !empty($entry['ctx']) ? json_encode($entry['ctx'], JSON_UNESCAPED_SLASHES) : '-';
                        $ua = $entry['ua'] ?? '';
                        $status = $entry['status'] ?? null;

                        if ($filterAction && strtolower($action) !== strtolower($filterAction)) continue;

                        switch(strtolower($action)){
                            case 'login': $badge='ok'; break;
                            case 'logout': $badge='warn'; break;
                            case 'totp_reset':
                            case 'delete_user': $badge='crit'; break;
                            default: $badge='unknown';
                        }
                        
                        $tsFormatted = $ts ? (new DateTime($ts))->format('d/m/Y H:i:s') : '';

                        echo '<tr class="row-'.$badge.'">';
                        echo '<td>' . htmlspecialchars($tsFormatted) . '</td>';
                        echo '<td>' . htmlspecialchars($ip) . '</td>';
                        echo '<td>' . htmlspecialchars($username) . '</td>';
                        echo '<td><span class="badge '.$badge.'">' . htmlspecialchars($action);
                        if ($badge === 'crit') echo ' ';
                        echo '</span></td>';
                        echo '<td>' . htmlspecialchars($ctx) . '</td>';
                        echo '<td>' . htmlspecialchars($ua) . '</td>';

                        // Gestion du statut
                        if (strtolower($action) === 'delete_user' && $status !== 'verifiee') {
                            echo '<td>
                                <span class="status suspecte"> Suspecte</span>
                                <form method="post" action="verify_log.php" class="inline-form">
                                    <input type="hidden" name="line" value="'.htmlspecialchars($line).'">
                                    <button class="btn btn-success btn-sm">Vérifier</button>
                                </form>
                            </td>';
                        } elseif ($status === 'verifiee') {
                            echo '<td><span class="status ok"> Vérifiée</span></td>';
                        } else {
                            echo '<td><span class="status ok"> Normal</span></td>';
                        }

                        echo '</tr>';
                    }

                    echo '<tr><td colspan="7" class="pagination">';
                    for ($i=1; $i<=$totalPages; $i++) {
                        $link = '?page='.$i.($filterAction ? '&action='.$filterAction : '');
                        echo '<a href="'.$link.'" class="page-link '.($i==$page?'active':'').'">'.$i.'</a> ';
                    }
                    echo '</td></tr>';
                } else {
                    echo '<tr><td colspan="7">Aucun journal trouvé.</td></tr>';
                }
                ?>
            </tbody>
        </table>
    </div>
</div>

<style>
body { background:#121212; color:#e0e0e0; font-family:Arial, sans-serif; }
h1.page-title { color:#fff; margin-bottom:20px; }
.card { padding:20px; border-radius:8px; background:#1e1e1e; }
.shadow-lg { box-shadow:0 4px 12px rgba(0,0,0,0.6); }
.toolbar { display:flex; justify-content:space-between; align-items:center; margin-bottom:15px; }
.table-container { border:1px solid #333; border-radius:6px; overflow:hidden; }
.table { width:100%; border-collapse:collapse; }
.table th { background:#2a2a2a; padding:10px; text-align:left; color:#ddd; }
.table td { padding:8px; border-bottom:1px solid #333; }
.table-striped tr:nth-child(even) { background:#1a1a1a; }
.table-hover tr:hover { background:#2a2a2a; }
.badge { padding:4px 8px; border-radius:4px; font-weight:bold; }
.badge.ok { background:#2e7d32; color:#fff; }
.badge.warn { background:#f9a825; color:#000; }
.badge.crit { background:#c62828; color:#fff; }
.badge.unknown { background:#616161; color:#fff; }
.row-crit { font-weight:bold; }
.status.suspecte { color:#ff5252; font-weight:bold; }
.status.ok { color:#4caf50; font-weight:bold; }
.btn { padding:6px 12px; border:none; border-radius:4px; cursor:pointer; text-decoration:none; }
.btn-primary { background:#1976d2; color:#fff; }
.btn-secondary { background:#424242; color:#fff; }
.btn-success { background:#388e3c; color:#fff; }
.btn-sm { padding:4px 8px; font-size:0.8em; }
.inline-form { display:inline; }
.pagination { text-align:center; padding:10px; }
.page-link { margin:0 3px; padding:4px 8px; border:1px solid #555; border-radius:4px; text-decoration:none; color:#ccc; }
.page-link.active { background:#1976d2; color:#fff; border-color:#1976d2; }
</style>

<?php include __DIR__ . '/../includes/footer.php'; ?>
