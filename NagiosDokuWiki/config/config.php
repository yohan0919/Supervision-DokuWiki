<?php
// config/config.php

return [

    // Chemin de l’instance DokuWiki à superviser (chemin système, relatif à ce fichier)
    'dokuwiki_path' => realpath(__DIR__ . '/../..') . '/bts_sio',

    // URL publique de DokuWiki pour test HTTP (ajustez selon votre domaine)
    // Exemple: https://www.example.com/doku.php
    'dokuwiki_url'  => (isset($_SERVER['HTTPS']) ? 'https://' : 'http://')
        . ($_SERVER['HTTP_HOST'] ?? 'www.cours-reseaux.fr')
        . dirname(dirname($_SERVER['SCRIPT_NAME'] ?? '/nagios/public/index.php'))
        . '/bts_sio/doku.php',

    // SQLite
    'sqlite_path'   => __DIR__ . '/../sqlite/supervision.sqlite',   

    // Journal
    'journal_path'  => __DIR__ . '/../logs/journal.log',

    // Sécurité
    'session_name'        => 'supv_session',
    'session_cookie_life' => 0, // session
    'csrf_key'            => 'csrf_token',

'date_default_timezone_set' => 'Europe/Paris',

    // TOTP / QR
    'issuer'              => 'DokuWiki-Supervision',
    'allow_external_qr'   => true, // utilise Google Chart API pour le QR (sinon affiche l’URL/secret)

    // Supervision – seuils (ajustez à vos quotas LWS)
    'thresholds' => [
        'disk_warn_percent'       => 85,  // % d’occupation
        'disk_crit_percent'       => 95,
        'cache_warn_mb'           => 200, // taille du cache
        'cache_crit_mb'           => 500,
        'latency_warn_ms'         => 800, // latence HTTP
        'latency_crit_ms'         => 2000,
        'config_recent_days_warn' => 3,   // modifs récentes de conf
    ],

    // Plugins requis (optionnel)
    'required_plugins' => [
        // 'acl', 'config', ...
    ],

    // Optionnel: tenter de récupérer la version DokuWiki upstream (nécessite sortie HTTP)
    'check_remote_version' => false,
];
