<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/functions.php';

$config = require __DIR__ . '/../config/config.php';
$pdo = db($config);

start_secure_session($config);
$user = current_user($pdo);
require_role($user, ['admin','superadmin']);

$logFile = $config['journal_path'] ?? __DIR__ . '/../logs/journal.log';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['line'])) {
    $lineToVerify = trim($_POST['line']);

    if (file_exists($logFile)) {
        $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $newLines = [];

        foreach ($lines as $line) {
            $decoded = json_decode($line, true);

            if ($decoded && $line === $lineToVerify) {
                // Ajoute ou modifie le champ "status"
                $decoded['status'] = 'verifiee';
                $line = json_encode($decoded, JSON_UNESCAPED_SLASHES);
            }

            $newLines[] = $line;
        }

        // Réécriture du fichier
        file_put_contents($logFile, implode(PHP_EOL, $newLines) . PHP_EOL, LOCK_EX);

        $_SESSION['flash_message'] = "L'action a été marquée comme vérifiée.";
    }
}

// Retour au journal
header("Location: journal.php");
exit;
