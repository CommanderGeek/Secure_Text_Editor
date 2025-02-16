package com.ste;

import DTOs.EncryptionRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import services.EncryptionService;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.Security;

import static junit.framework.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.*;

public class EncryptionTest {

    private Encryption encryption;
    private EncryptionService encryptionService;
    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        encryption = new Encryption();
        encryptionService = new EncryptionService();
        System.setOut(new PrintStream(outContent)); // Redirect console output to capture logs
    }

    @Test
    void testEncryptAES_CBC_Valid() {
        EncryptionRequest request = new EncryptionRequest();
        request.setText("This is a test message");
        request.setEncryptionType("AES");
        request.setKeySize("128_SYM");
        request.setPadding("PKCS7Padding_SYM");
        request.setBlockMode("CBC_SYM");
        request.setMac("SHA-256_MAC");
        request.setPassword("");
        request.setSignatureType("");
        request.setKey("");

        String encryptedText = encryption.encryptText(request);

        assertNotNull(encryptedText, "Encryption should return a valid encrypted string");
        assertTrue(encryptedText.length() > 10, "Encrypted text should be longer than input text");
        System.out.println("AES-CBC Encrypted Output: " + encryptedText);
    }

    @Test
    void testEncryptPBE_Valid() {
        EncryptionRequest request = new EncryptionRequest();
        request.setText("Secret Message for PBE");
        request.setEncryptionType("ChaCha7539");
        request.setKeySize("256_SYM");
        request.setPadding("");
        request.setBlockMode("");
        request.setMac("SHA-256_MAC");
        request.setPassword("SuperSecretPassword!");
        request.setSignatureType("");
        request.setKey("");

        String encryptedText = encryption.encryptText(request);

        assertNotNull(encryptedText, "Encryption should return a valid encrypted string");
        assertTrue(encryptedText.length() > 10, "Encrypted text should be longer than input text");
        assertTrue(!encryptedText.equals(request.getText()), "Encrypted text should be different");
        System.out.println("PBE Encrypted Output: " + encryptedText);
    }

    @Test
    void testEncryptWithSignature() {
        EncryptionRequest request = new EncryptionRequest();
        request.setText("Signed Message");
        request.setEncryptionType("AES");
        request.setKeySize("128_SYM");
        request.setPadding("PKCS7Padding_SYM");
        request.setBlockMode("CBC_SYM");
        request.setMac("");
        request.setPassword("");
        request.setSignatureType("SHA256withDSA");
        request.setKey("");

        String encryptedText = encryption.encryptText(request);

        assertNotNull(encryptedText, "Encryption should return a valid encrypted string");
        assertTrue(encryptedText.length() > 10, "Encrypted text should be longer than input text");
        System.out.println("Signed AES-CBC Encrypted Output: " + encryptedText);
    }


    @Test
    void testGenerateKey_ValidAES() {
        EncryptionRequest request = new EncryptionRequest();
        request.setEncryptionType("AES");
        request.setKeySize("256_SYM");

        String keyHex = encryption.generateKey(request);

        assertNotNull(keyHex, "Generated key should not be null");
        assertEquals(64, keyHex.length(), "AES-256 key should be 64 hex characters");
        System.out.println("Generated AES-256 Key: " + keyHex);
    }

    @Test
    void testGenerateKey_ValidPBE() {
        EncryptionRequest request = new EncryptionRequest();
        request.setEncryptionType("AES_PAS");
        request.setKeySize("256_SYM");

        String keyHex = encryption.generateKey(request);

        assertNotNull(keyHex, "Generated key should not be null");
        assertEquals(64, keyHex.length(), "AES 256-bit key should be 64 hex characters");
        System.out.println("Generated PBE Key: " + keyHex);
    }

    @Test
    void testGenerateKey_InvalidAlgorithm() {
        EncryptionRequest request = new EncryptionRequest();
        request.setEncryptionType("INVALID_ALGO");
        request.setKeySize("128_SYM");

        Exception exception = assertThrows(Exception.class, () -> encryption.generateKey(request));
        String consoleOutput = outContent.toString();
        assertTrue(consoleOutput.contains("The given Algorithm does not exists"),
                "Console should print an error message for invalid algorithm");
    }

    /**
     * **Generates a temporary test AES key (hex-encoded)**
     * @param algorithm Algorithm type (AES, PBE, etc.)
     * @param keySize Key size in bits (128, 256)
     * @return Hex-encoded key string
     */
    private String generateTestKey(String algorithm, int keySize) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();
        return Hex.toHexString(secretKey.getEncoded());
    }
}
