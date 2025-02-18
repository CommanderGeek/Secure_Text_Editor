package com.ste;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

//source: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES
public class AESCBCKnownAnswerTest {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "CBC";
    private static final String PADDING = "NoPadding";

    @BeforeAll
    static void setUp() {
        Security.addProvider(new BouncyCastleProvider()); // Ensure Bouncy Castle is available
    }

    @Test
    void testAES128_CBC_Encrypt_KAT() throws Exception {
        runKnownAnswerEncryptionTest(
                "00000000000000000000000000000000", // Key
                "00000000000000000000000000000000", // IV
                "f34481ec3cc627bacd5dc3fb08f273e6", // Plaintext
                "0336763e966d92595a567cc9ce537f5e"  // Expected Ciphertext
        );

        runKnownAnswerEncryptionTest(
                "00000000000000000000000000000000",
                "00000000000000000000000000000000",
                "9798c4640bad75c7c3227db910174e72",
                "a9a1631bf4996954ebc093957b234589"
        );
    }

    @Test
    void testAES128_CBC_Decrypt_KAT() throws Exception {
        runKnownAnswerDecryptionTest(
                "00000000000000000000000000000000", // Key
                "00000000000000000000000000000000", // IV
                "0336763e966d92595a567cc9ce537f5e", // Ciphertext
                "f34481ec3cc627bacd5dc3fb08f273e6"  // Expected Plaintext
        );

        runKnownAnswerDecryptionTest(
                "00000000000000000000000000000000",
                "00000000000000000000000000000000",
                "a9a1631bf4996954ebc093957b234589",
                "9798c4640bad75c7c3227db910174e72"
        );
    }

    /**
     * Runs a Known Answer Test (KAT) for AES-128 CBC encryption using Bouncy Castle.
     *
     * @param keyHex       AES key in hexadecimal format (128-bit).
     * @param ivHex        IV in hexadecimal format (128-bit).
     * @param plaintextHex Plaintext in hexadecimal format (128-bit).
     * @param expectedCiphertextHex Expected ciphertext in hexadecimal format (128-bit).
     */
    private void runKnownAnswerEncryptionTest(String keyHex, String ivHex, String plaintextHex, String expectedCiphertextHex) throws Exception {
        byte[] keyBytes = Hex.decode(keyHex);
        byte[] ivBytes = Hex.decode(ivHex);
        byte[] plaintextBytes = Hex.decode(plaintextHex);
        byte[] expectedCiphertextBytes = Hex.decode(expectedCiphertextHex);

        SecretKey key = new SecretKeySpec(keyBytes, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));

        byte[] encryptedBytes = cipher.doFinal(plaintextBytes);

        assertNotNull(encryptedBytes, "Encryption should return valid output");
        assertArrayEquals(expectedCiphertextBytes, encryptedBytes, "Ciphertext should match known answer");
    }

    /**
     * Runs a Known Answer Test (KAT) for AES-128 CBC decryption using Bouncy Castle.
     *
     * @param keyHex       AES key in hexadecimal format (128-bit).
     * @param ivHex        IV in hexadecimal format (128-bit).
     * @param ciphertextHex Ciphertext in hexadecimal format (128-bit).
     * @param expectedPlaintextHex Expected plaintext in hexadecimal format (128-bit).
     */
    private void runKnownAnswerDecryptionTest(String keyHex, String ivHex, String ciphertextHex, String expectedPlaintextHex) throws Exception {
        byte[] keyBytes = Hex.decode(keyHex);
        byte[] ivBytes = Hex.decode(ivHex);
        byte[] ciphertextBytes = Hex.decode(ciphertextHex);
        byte[] expectedPlaintextBytes = Hex.decode(expectedPlaintextHex);

        SecretKey key = new SecretKeySpec(keyBytes, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING, "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));

        byte[] decryptedBytes = cipher.doFinal(ciphertextBytes);

        assertNotNull(decryptedBytes, "Decryption should return valid output");
        assertArrayEquals(expectedPlaintextBytes, decryptedBytes, "Decrypted text should match known plaintext");
    }
}
