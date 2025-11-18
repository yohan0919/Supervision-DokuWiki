<?php
// includes/functions.php

function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

function ensure_dir(string $p): void { if (!is_dir($p)) @mkdir($p, 0775, true); }

function log_event(array $config, ?string $username, string $action, array $ctx = []): void {
    $file = $config['journal_path'];
    ensure_dir(dirname($file));
    $entry = [
        'ts' => gmdate('c'),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user' => $username,
        'action' => $action,
        'ctx' => $ctx,
        'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
    ];
    // JSONL append + newline
    @file_put_contents($file, json_encode($entry, JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND);
}

function badge(string $status): string {
    $map = [
        'OK' => ['🟢','ok'],
        'WARN' => ['🟡','warn'],
        'CRIT' => ['🔴','crit'],
        'UNKNOWN' => ['⚪','unknown'],
    ];
    [$emoji,$class] = $map[$status] ?? ['⚪','unknown'];
    return '<span class="badge ' . $class . '">' . $emoji . ' ' . e($status) . '</span>';
}

function worst_status(string ...$s): string {
    $rank = ['OK'=>0,'WARN'=>1,'CRIT'=>2,'UNKNOWN'=>3];
    $max = 'OK';
    foreach ($s as $x) if (($rank[$x] ?? 3) > ($rank[$max] ?? -1)) $max = $x;
    return $max;
}

function bytes_to_mb(int $b): float { return round($b / (1024*1024), 1); }

function dir_size(string $path): int {
    $size = 0;
    if (!is_dir($path)) return 0;
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $f) { if ($f->isFile()) $size += $f->getSize(); }
    return $size;
}

function csrf_token(array $config): string {
    if (empty($_SESSION[$config['csrf_key']])) {
        $_SESSION[$config['csrf_key']] = bin2hex(random_bytes(32));
    }
    return $_SESSION[$config['csrf_key']];
}

function csrf_field(array $config): string {
    return '<input type="hidden" name="_token" value="' . e(csrf_token($config)) . '">';
}

function csrf_check(array $config): void {
    if (($_POST['_token'] ?? '') !== ($_SESSION[$config['csrf_key']] ?? null)) {
        http_response_code(419); die('CSRF token invalide');
    }
}

// En-têtes de sécurité de base (à appeler avant tout output)
function send_security_headers(): void {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
}