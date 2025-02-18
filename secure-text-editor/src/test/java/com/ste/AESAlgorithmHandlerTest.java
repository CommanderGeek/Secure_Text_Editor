package com.ste;

import Builder.KeyBuilder;
import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import Handler.AESAlgorithmHandler;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.Security;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.*;

class AESAlgorithmHandlerTest {

    private AESAlgorithmHandler handler;
    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        handler = new AESAlgorithmHandler();
        System.setOut(new PrintStream(outContent));
    }

    @Test
    void testEncryptAndDecrypt_ValidAES() {
        String originalText = "Sensitive data for AES encryption";

        EncryptionMetadata metadata = new EncryptionMetadata();
        metadata.setAlgorithm("AES");
        metadata.setMode("CBC");
        metadata.setPadding("PKCS7Padding");
        metadata.setKeySize("128");

        SecretKey key = new KeyBuilder()
                .setAlgorithm("AES")
                .setKeySize(128)
                .build();
        metadata.setKey(Hex.toHexString(key.getEncoded()));

        IntegrityData integrityData = new IntegrityData("", "");

        String encryptedFileString = handler.encrypt(originalText.getBytes(), metadata, integrityData);
        String[] parts = encryptedFileString.split("\\.");// Split on the first dot
        String encryptedText = parts[1];
        assertNotNull(encryptedText, "Encryption should return a valid encrypted string");
        assertTrue(encryptedText.length() > 10, "Encrypted text should be longer than input text");

        // **Decrypt Data**
        String decryptedText = handler.decrypt(encryptedText, metadata);
        assertNotNull(decryptedText, "Decryption should return a valid string");
        assertEquals("Decrypted text should match original text", originalText, decryptedText);

        System.out.println("Encrypted AES Output: " + encryptedText);
        System.out.println("Decrypted AES Output: " + decryptedText);
    }

    @Test
    void testEncryptWithMissingKey() {
        String originalText = "This is a test message without a key";

        EncryptionMetadata metadata = new EncryptionMetadata();
        metadata.setAlgorithm("AES");
        metadata.setMode("CBC");
        metadata.setPadding("PKCS7Padding");
        metadata.setKeySize("128");

        IntegrityData integrityData = new IntegrityData("", "");

        String encryptedFileString = handler.encrypt(originalText.getBytes(), metadata, integrityData);
        String[] parts = encryptedFileString.split("\\.");// Split on the first dot
        String encryptedText = parts[1];
        assertNotNull(encryptedText, "Encryption should still work!");
        assertFalse(encryptedText.isEmpty(), "Encrypted text should exist");

    }

    @Test
    void testDecryptWithInvalidCiphertext() {

        String originalText = "This is a test message without a key";

        EncryptionMetadata metadata = new EncryptionMetadata();
        metadata.setAlgorithm("AES");
        metadata.setMode("GCM");
        metadata.setPadding("NoPadding");
        metadata.setKeySize("256");

        // **Generate AES Key**
        SecretKey key = new KeyBuilder()
                .setAlgorithm("AES")
                .setKeySize(256)
                .build();
        metadata.setKey(Hex.toHexString(key.getEncoded()));

        IntegrityData integrityData = new IntegrityData("", "");
        String encryptedFileString = handler.encrypt(originalText.getBytes(), metadata, integrityData);
        String[] parts = encryptedFileString.split("\\.");// Split on the first dot
        String encryptedText = parts[1];
        assertNotNull(encryptedText, "Encryption should return a valid encrypted string");
        assertTrue(encryptedText.length() > 10, "Encrypted text should be longer than input text");

        encryptedText = Hex.toHexString("invalidcipherdata".getBytes());

        String finalEncryptedText = encryptedText;
        assertThrows(Exception.class, () -> handler.decrypt(finalEncryptedText, metadata));
        String consoleOutput = outContent.toString();
        assertTrue(consoleOutput.contains("Bad padding") ||
                        consoleOutput.contains("IllegalBlockSizeException") || consoleOutput.contains("mac check in GCM failed"),
                "Decryption should fail with invalid ciphertext");
    }
}