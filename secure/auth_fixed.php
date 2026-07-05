<?php
// auth.php (REMEDIATED)
require_once 'db_config.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $inputKey = $_POST['auth_key'] ?? '';

    // FIX 1 (Flaw D): semantic character count, not raw byte count.
    // strlen() bypasses on multi-byte UTF-8; mb_strlen() measures the
    // actual unit the boundary check was meant to protect.
    if (mb_strlen($inputKey, 'UTF-8') > 256) {
        http_response_code(400);
        die("Invalid request: key length exceeds policy.");
    }

    // Defense-in-depth: cap raw byte expansion too, in case of
    // combining-character amplification attacks.
    if (strlen($inputKey) > 1024) {
        http_response_code(400);
        die("Invalid request: byte length exceeds policy.");
    }

    // FIX 2 (Flaw E): MD5 -> Argon2id. Hash is fetched per-user from
    // the DB, never hardcoded in source.
    $stmt = $pdo->prepare("SELECT auth_key_hash FROM staff_credentials WHERE username = :u");
    $stmt->execute([':u' => $_POST['username'] ?? '']);
    $stored_hash = $stmt->fetchColumn();

    if ($stored_hash !== false && password_verify($inputKey, $stored_hash)) {
        echo "Access Granted.";
    } else {
        // Uniform response on failure — avoids leaking whether the
        // username existed (timing/oracle behavior).
        http_response_code(401);
        echo "Access Denied.";
    }
}

// Used when provisioning/rotating a staff credential (not part of the request path):
function hashNewAuthKey(string $key): string {
    return password_hash($key, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536, // 64 MiB
        'time_cost'   => 4,
        'threads'     => 2,
    ]);
}
