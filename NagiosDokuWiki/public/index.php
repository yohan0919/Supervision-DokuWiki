<?php
// public/index.php
$config = require __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';

start_secure_session($config);
$pdo = db($config);

// si connecté -> supervision, sinon -> login
if (isset($_SESSION['uid'])) {
    header('Location: supervision.php');
    exit;
}
header('Location: login.php');
exit;
