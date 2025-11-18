<?php
// includes/totp.php – TOTP RFC 6238

function base32_encode(string $data): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    for ($i = 0; $i < strlen($data); $i++) {
        $bits .= str_pad(decbin(ord($data[$i])), 8, '0', STR_PAD_LEFT);
    }
    $chunks = str_split($bits, 5);
    $out = '';
    foreach ($chunks as $chunk) {
        $out .= $alphabet[bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
    }
    // Ajout du padding =
    while (strlen($out) % 8 !== 0) {
        $out .= '=';
    }
    return $out;
}

function base32_decode(string $b32): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $b32 = strtoupper(str_replace('=', '', $b32));
    $map = array_flip(str_split($alphabet));
    $bits = '';
    for ($i = 0; $i < strlen($b32); $i++) {
        if (!isset($map[$b32[$i]])) continue;
        $bits .= str_pad(decbin($map[$b32[$i]]), 5, '0', STR_PAD_LEFT);
    }
    $output = '';
    foreach (str_split($bits, 8) as $byte) {
        if (strlen($byte) === 8) $output .= chr(bindec($byte));
    }
    return $output;
}

function totp_random_secret(int $bytes = 20): string {
    return base32_encode(random_bytes($bytes));
}

function hotp(string $secret, int $counter, int $digits = 6): string {
    $key = base32_decode($secret);
    $binCounter = pack('N*', 0) . pack('N*', $counter); // 8-byte big endian
    $hash = hash_hmac('sha1', $binCounter, $key, true);
    $offset = ord(substr($hash, -1)) & 0xf;
    $code = ( (ord($hash[$offset]) & 0x7f) << 24 ) |
            ( (ord($hash[$offset+1]) & 0xff) << 16 ) |
            ( (ord($hash[$offset+2]) & 0xff) << 8 ) |
            ( (ord($hash[$offset+3]) & 0xff) );
    $code %= 10 ** $digits;
    return str_pad((string)$code, $digits, '0', STR_PAD_LEFT);
}

function totp_now(string $secret, int $period = 30, int $digits = 6): string {
    $counter = (int) floor(time() / $period);
    return hotp($secret, $counter, $digits);
}

function totp_verify(string $secret, string $code, int $period = 30, int $digits = 6, int $window = 1): bool {
    $t = (int) floor(time() / $period);
    $code = preg_replace('/\s+/', '', $code);
    for ($i = -$window; $i <= $window; $i++) {
        if (hash_equals(hotp($secret, $t + $i, $digits), $code)) {
            return true;
        }
    }
    return false;
}

function otpauth_uri(string $issuer, string $account, string $secret): string {
    $label = rawurlencode($issuer . ':' . $account);
    $params = http_build_query([
        'secret'   => $secret,
        'issuer'   => $issuer,
        'algorithm'=> 'SHA1',
        'digits'   => 6,
        'period'   => 30,
    ]);
    return "otpauth://totp/{$label}?{$params}";
}