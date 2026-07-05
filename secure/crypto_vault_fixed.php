<?php
// crypto_vault.php (REMEDIATED)
require_once 'CryptographicIntegrityException.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $medical_payload = $_POST['payload'];

    // FIX (Flaw G): key loaded from environment, never hardcoded in source.
    $secret_key = getenv('MEDVAULT_KEY'); // 32 raw bytes, base64-decoded
    if ($secret_key === false) {
        http_response_code(500);
        die("Server misconfiguration.");
    }
    $secret_key = base64_decode($secret_key);

    // FIX (Flaw F): AES-256-GCM — AEAD mode, gives confidentiality
    // + integrity + authenticity in one primitive. IV must be fresh
    // and random per encryption; never reused with the same key.
    $iv  = random_bytes(12); // 96-bit IV, per NIST SP 800-38D
    $tag = '';
    $ciphertext = openssl_encrypt(
        $medical_payload,
        'aes-256-gcm',
        $secret_key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,   // auth tag written by reference
        '',     // no AAD used here
        16      // 128-bit tag length
    );

    if ($ciphertext === false) {
        http_response_code(500);
        die("Encryption failure.");
    }

    echo json_encode([
        "status" => "vaulted",
        "data"   => base64_encode($ciphertext),
        "iv"     => base64_encode($iv),
        "tag"    => base64_encode($tag),
    ]);
}

/**
 * Decryption helper — demonstrates the isolated, typed failure state
 * on tag mismatch (Flaw fix for the "runtime trap" noted in the
 * original file comment).
 */
function decryptVault(string $data, string $iv, string $tag, string $key): string
{
    $plaintext = openssl_decrypt(
        base64_decode($data),
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        base64_decode($iv),
        base64_decode($tag)
    );

    if ($plaintext === false) {
        // Typed exception instead of letting `false` silently coerce
        // to an empty string downstream.
        throw new CryptographicIntegrityException(
            "AEAD authentication failed: ciphertext or tag has been tampered with."
        );
    }

    return $plaintext;
}
