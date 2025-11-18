<?php
require_once __DIR__ . '/../includes/auth.php';
$config = require __DIR__ . '/../config/config.php';
$pdo = db($config);

start_secure_session($config);
$user = current_user($pdo);
require_role($user, ['user', 'admin', 'superadmin']);

$dokuwikiPath = realpath(__DIR__ . '/../../bts_sio/');
$etat = [];
$valeur = [];
$details = [];

function listFiles($dir) {
    $files = [];
    if (is_dir($dir)) {
        foreach (glob("$dir/*") as $file) {
            $files[] = basename($file);
        }
    }
    return $files;
}

function checkPermissions($dir) {
    $perms = fileperms($dir);
    $oct = substr(sprintf('%o', $perms), -4);
    $warn = ($oct === "0777"); // trop ouvert
    return [$oct, $warn];
}

if ($dokuwikiPath && is_dir($dokuwikiPath)) {
    $etat['Répertoire DokuWiki'] = 'OK';
    $valeur['Répertoire DokuWiki'] = $dokuwikiPath;

    $pagesDir = $dokuwikiPath . '/data/pages';
    $mediaDir = $dokuwikiPath . '/data/media';
    $confDir = $dokuwikiPath . '/conf';

    // Pages
    $pages = listFiles($pagesDir);
    $etat['Pages'] = (count($pages) > 0) ? 'OK' : 'Vide/Manquant';
    $valeur['Pages'] = count($pages) . ' fichiers';
    $details['Pages'] = $pages;

    // Médias
    $medias = listFiles($mediaDir);
    $etat['Médias'] = (count($medias) > 0) ? 'OK' : 'Vide/Manquant';
    $valeur['Médias'] = count($medias) . ' fichiers';
    $details['Médias'] = $medias;

    // Permissions
    [$permPages, $warnPages] = checkPermissions($pagesDir);
    $etat['Permissions pages'] = is_writable($pagesDir) ? 'OK' : 'Non inscriptible';
    $valeur['Permissions pages'] = $permPages . ($warnPages ? ' ⚠️ Trop ouvert' : '');

    [$permMedia, $warnMedia] = checkPermissions($mediaDir);
    $etat['Permissions media'] = is_writable($mediaDir) ? 'OK' : 'Non inscriptible';
    $valeur['Permissions media'] = $permMedia . ($warnMedia ? ' ⚠️ Trop ouvert' : '');

    [$permConf, $warnConf] = checkPermissions($confDir);
    $etat['Permissions conf'] = is_writable($confDir) ? 'OK' : 'Non inscriptible';
    $valeur['Permissions conf'] = $permConf . ($warnConf ? ' ⚠️ Trop ouvert' : '');
}

include __DIR__ . '/../includes/header.php';
?>

<section class="page-header">
    <h1 class="page-title">Tableau de supervision</h1>
    <div class="legend">
      <span class="badge ok">OK</span>
      <span class="badge warn">WARN</span>
      <span class="badge crit">CRIT</span>
      <span class="badge unknown">UNKNOWN</span>
    </div>
</section>

<h1>DokuWiki — État du système</h1>

<div class="card">
    <table class="table">
        <thead>
            <tr>
                <th>Élément</th>
                <th>État</th>
                <th>Valeur</th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($etat as $cle => $val): 
            $badgeClass = ($val === 'OK') ? 'ok' : 'warn';
        ?>
            <tr class="row-<?= $badgeClass ?>">
                <td><?= htmlspecialchars($cle) ?></td>
                <td><span class="badge <?= $badgeClass ?>"><?= htmlspecialchars($val) ?></span></td>
                <td><?= htmlspecialchars($valeur[$cle]) ?></td>
            </tr>
            <?php if (!empty($details[$cle])): ?>
            <tr>
                <td colspan="3">
                    <details>
                        <summary>Voir les fichiers <?= htmlspecialchars($cle) ?></summary>
                        <ul>
                            <?php foreach ($details[$cle] as $f): ?>
                                <li><a href="<?= htmlspecialchars($f) ?>" target="_blank"><?= htmlspecialchars($f) ?></a></li>
                            <?php endforeach; ?>
                        </ul>
                    </details>
                </td>
            </tr>
            <?php endif; ?>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php include __DIR__ . '/../includes/footer.php'; ?>
