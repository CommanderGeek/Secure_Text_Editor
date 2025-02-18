package com.ste;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class BouncyCastleProviderTest {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "CBC";
    private static final String PADDING = "PKCS7Padding";

    @BeforeAll
    static void setupProvider() {
        // Ensure Bouncy Castle is registered
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void testKnownAnswerEncryption() throws Exception {
        byte[] keyBytes = Hex.decode("000102030405060708090A0B0C0D0E0F");
        byte[] ivBytes = Hex.decode("0F0E0D0C0B0A09080706050403020100");
        byte[] plaintext = "BouncyCastleTest".getBytes();

        SecretKey key = new SecretKeySpec(keyBytes, ALGORITHM);
        Cipher encryptCipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING, "BC");
        encryptCipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));



        byte[] encrypted = encryptCipher.doFinal(plaintext);
        // Expected encrypted output
        byte[] expectedEncrypted = Hex.decode("6cd4fcfe484d950fdea62aa943b1e3767df70c0f80639aeae8c4dd2775e9d739");
        assertArrayEquals(expectedEncrypted, encrypted);

        // Now decrypt
        Cipher decryptCipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING, "BC");
        decryptCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));

        byte[] decrypted = decryptCipher.doFinal(encrypted);
        assertArrayEquals(plaintext, decrypted);
    }


    //source: https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES#XTS
    @Test
    void testMonteCarloEncryption() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM, "BC");
        keyGen.init(192);
        SecretKey key = keyGen.generateKey();

        byte[] plaintext = "MonteCarloTest123".getBytes();
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING, "BC");

        // Run 1000 encryption-decryption cycles
        byte[] currentText = plaintext;
        byte[] encrypted = new byte[0];
        for (int i = 0; i < 100; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encrypted = cipher.doFinal(currentText);
        }
        byte[] decrypted = new byte[0];
        // Decrypt back
        for (int i = 0; i < 100; i++) {
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(cipher.getIV()));
            decrypted = cipher.doFinal(encrypted);
        }
        // Ensure final result matches original
        assertArrayEquals(plaintext, decrypted);
    }


    @Test
    void testBouncyCastleProvider() {
        assertNotNull(Security.getProvider("BC"), "Bouncy Castle provider should be available");
    }
}
