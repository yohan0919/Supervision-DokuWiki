<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/db.php';

$config = require __DIR__ . '/../config/config.php';
$pdo = db($config);

start_secure_session($config);
$user = current_user($pdo);
require_role($user, ['admin','superadmin']);

$logFile = $config['journal_path'] ?? __DIR__ . '/../logs/journal.log';

// En-têtes HTTP pour forcer le téléchargement CSV
header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename="journal.csv"');

// Ouvre la sortie standard
$output = fopen('php://output', 'w');

// Ligne d’en-tête
fputcsv($output, ['Date/Heure', 'IP', 'Utilisateur', 'Action', 'Contexte', 'Agent utilisateur', 'Statut']);

if (file_exists($logFile)) {
    $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

    foreach ($lines as $line) {
        $entry = json_decode($line, true);
        if (!$entry) continue;

        $ts = $entry['ts'] ?? '';
        $ip = $entry['ip'] ?? '';
        $username = $entry['user'] ?? '';
        $action = $entry['action'] ?? '';
        $ctx = isset($entry['ctx']) && !empty($entry['ctx']) ? json_encode($entry['ctx'], JSON_UNESCAPED_SLASHES) : '-';
        $ua = $entry['ua'] ?? '';
        $status = $entry['status'] ?? (strtolower($action)==='delete_user' ? 'suspecte' : 'normal');

        fputcsv($output, [$ts, $ip, $username, $action, $ctx, $ua, $status]);
    }
} else {
    fputcsv($output, ['Aucun journal trouvé']);
}

fclose($output);
exit;
