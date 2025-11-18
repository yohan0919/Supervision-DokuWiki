<?php
// includes/checks.php – Contrôles pour DokuWiki

require_once __DIR__ . '/functions.php';

function check_http(string $url, int $warnMs, int $critMs): array {
    if (!function_exists('curl_init')) {
        return ['status'=>'UNKNOWN','msg'=>'curl absent','latency_ms'=>null,'code'=>null];
    }
    $start = microtime(true);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_NOBODY => false,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_USERAGENT => 'Supervision/1.0',
    ]);
    $response = curl_exec($ch);
    $info = curl_getinfo($ch);
    $err  = curl_error($ch);
    curl_close($ch);

    if ($response === false) {
        return ['status'=>'CRIT','msg'=>'HTTP failure: '. $err,'latency_ms'=>null,'code'=>null];
    }
    $latency = (int)round((microtime(true) - $start)*1000);
    $code = (int)($info['http_code'] ?? 0);
    if ($code >= 500 || $code === 0) return ['status'=>'CRIT','msg'=>'HTTP '. $code,'latency_ms'=>$latency,'code'=>$code];
    if ($code >= 400) return ['status'=>'WARN','msg'=>'HTTP '. $code,'latency_ms'=>$latency,'code'=>$code];
    if ($latency > $critMs) return ['status'=>'CRIT','msg'=>'Latence élevée','latency_ms'=>$latency,'code'=>$code];
    if ($latency > $warnMs) return ['status'=>'WARN','msg'=>'Latence modérée','latency_ms'=>$latency,'code'=>$code];
    return ['status'=>'OK','msg'=>'OK','latency_ms'=>$latency,'code'=>$code];
}

function check_path_exists(string $p): array {
    if (file_exists($p)) return ['status'=>'OK','msg'=>'Existant'];
    return ['status'=>'CRIT','msg'=>'Chemin introuvable'];
}

function check_writable(string $p): array {
    if (!file_exists($p)) return ['status'=>'CRIT','msg'=>'Introuvable'];
    if (is_writable($p)) return ['status'=>'OK','msg'=>'Inscriptible'];
    return ['status'=>'WARN','msg'=>'Non inscriptible'];
}

function check_disk_usage(string $dir, int $warnPct, int $critPct): array {
    if (!is_dir($dir)) return ['status'=>'UNKNOWN','msg'=>'Dir manquant'];
    $df = @disk_free_space($dir);
    $dt = @disk_total_space($dir);
    if ($df === false || $dt === false || $dt == 0) return ['status'=>'UNKNOWN','msg'=>'Espace inconnu'];
    $usedPct = (int)round((1 - ($df/$dt))*100);
    if ($usedPct >= $critPct) return ['status'=>'CRIT','msg'=>"Occupation {$usedPct}%"];
    if ($usedPct >= $warnPct) return ['status'=>'WARN','msg'=>"Occupation {$usedPct}%"];
    return ['status'=>'OK','msg'=>"Occupation {$usedPct}%"];
}

function check_dir_size_mb(string $dir, int $warnMb, int $critMb): array {
    if (!is_dir($dir)) return ['status'=>'UNKNOWN','msg'=>'Dir manquant'];
    $bytes = dir_size($dir);
    $mb = (int)round($bytes / (1024*1024));
    if ($mb >= $critMb) return ['status'=>'CRIT','msg'=>"Taille {$mb} MiB"];
    if ($mb >= $warnMb) return ['status'=>'WARN','msg'=>"Taille {$mb} MiB"];
    return ['status'=>'OK','msg'=>"Taille {$mb} MiB"];
}

function check_plugins(string $pluginsDir, array $required = []): array {
    if (!is_dir($pluginsDir)) return ['status'=>'UNKNOWN','msg'=>'plugins/ manquant'];
    $installed = [];
    foreach (glob($pluginsDir . '/*', GLOB_ONLYDIR) as $d) {
        $installed[] = basename($d);
    }
    $missing = array_values(array_diff($required, $installed));
    if ($missing) return ['status'=>'WARN','msg'=>'Plugins manquants: '.implode(',', $missing), 'installed'=>$installed];
    return ['status'=>'OK','msg'=>'Plugins OK', 'installed'=>$installed];
}

function check_config_files(string $confDir, int $recentDaysWarn): array {
    $files = ['dokuwiki.php','local.php'];
    $missing = [];$recent = [];
    foreach ($files as $f) {
        $p = $confDir . '/' . $f;
        if (!file_exists($p)) { $missing[] = $f; continue; }
        $ageDays = (int)floor((time() - filemtime($p)) / 86400);
        if ($ageDays <= $recentDaysWarn) $recent[] = "$f modifié il y a {$ageDays}j";
    }
    if ($missing) return ['status'=>'CRIT','msg'=>'Fichiers manquants: '.implode(',', $missing)];
    if ($recent) return ['status'=>'WARN','msg'=>implode(' | ', $recent)];
    return ['status'=>'OK','msg'=>'Configs OK'];
}

function check_cache_freshness(string $cacheDir): array {
    if (!is_dir($cacheDir)) return ['status'=>'UNKNOWN','msg'=>'cache/ manquant'];
    $latest = 0;
    foreach (glob($cacheDir.'/*') as $f) { $t = @filemtime($f); if ($t && $t > $latest) $latest = $t; }
    if ($latest === 0) return ['status'=>'WARN','msg'=>'Cache vide ?'];
    $ageMin = (int)floor((time() - $latest)/60);
    return ['status'=>'OK','msg'=>"Cache maj il y a {$ageMin} min"];
}

function check_version(string $dwRoot, bool $remote): array {
    $local = file_exists($dwRoot.'/VERSION') ? trim((string)@file_get_contents($dwRoot.'/VERSION')) : null;
    if (!$remote) return ['status'=>$local? 'OK':'UNKNOWN', 'msg'=>$local? 'VERSION '.$local : 'VERSION inconnue'];
    if (!function_exists('curl_init')) return ['status'=>'UNKNOWN','msg'=>'curl absent'];
    $ch = curl_init('https://raw.githubusercontent.com/splitbrain/dokuwiki/master/VERSION');
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>4]);
    $up = curl_exec($ch); curl_close($ch);
    $up = $up ? trim($up) : null;
    if (!$local && !$up) return ['status'=>'UNKNOWN','msg'=>'Versions inconnues'];
    if ($local && !$up) return ['status'=>'OK','msg'=>'VERSION '.$local.' (upstream inconnue)'];
    if (!$local && $up) return ['status'=>'WARN','msg'=>'Locale inconnue; upstream '.$up];
    if (version_compare($local, $up, '>=')) return ['status'=>'OK','msg'=>"A jour ($local)"];
    return ['status'=>'WARN','msg'=>"Upstream $up > local $local"];
}