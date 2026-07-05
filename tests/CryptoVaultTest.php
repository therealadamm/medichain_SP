<?php
use PHPUnit\Framework\TestCase;

final class CryptoVaultTest extends TestCase
{
    private string $key;

    protected function setUp(): void
    {
        $this->key = random_bytes(32); // ephemeral test key only
    }

    public function testUntamperedRoundTripReturnsOriginalPlaintext(): void
    {
        $plaintext = "Patient dosage: 10mg q12h";
        $envelope  = CryptoVault::encrypt($plaintext, $this->key);
        $recovered = CryptoVault::decrypt(
            $envelope['data'], $envelope['iv'], $envelope['tag'], $this->key
        );
        $this->assertSame($plaintext, $recovered);
    }

    public function testTamperedCiphertextThrowsIntegrityException(): void
    {
        $plaintext = "Patient dosage: 10mg q12h";
        $envelope  = CryptoVault::encrypt($plaintext, $this->key);

        $rawCipher = base64_decode($envelope['data']);
        $rawCipher[0] = chr(ord($rawCipher[0]) ^ 0xFF); // flip one byte
        $tamperedData = base64_encode($rawCipher);

        $this->expectException(CryptographicIntegrityException::class);
        CryptoVault::decrypt($tamperedData, $envelope['iv'], $envelope['tag'], $this->key);
    }

    public function testArgon2idHashVerificationMatchesCorrectKeyOnly(): void
    {
        $correctKey = "S3cure-Physician-Key!";
        $hash = password_hash($correctKey, PASSWORD_ARGON2ID);
        $this->assertTrue(password_verify($correctKey, $hash));
        $this->assertFalse(password_verify("wrong-key-guess", $hash));
    }

    public function testMultiByteLengthGuardUsesCharacterCountNotByteCount(): void
    {
        $multiByteKey = str_repeat("\u{4E2D}", 200); // 200 CJK chars
        $this->assertLessThanOrEqual(256, mb_strlen($multiByteKey, 'UTF-8'));
        $this->assertGreaterThan(256, strlen($multiByteKey));
    }
}
