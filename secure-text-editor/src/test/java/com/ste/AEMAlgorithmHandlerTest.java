package com.ste;


import Builder.KeyBuilder;
import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import Handler.AEMAlgorithmHandler;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import services.EncryptionService;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

class AEMAlgorithmHandlerTest {

    private AEMAlgorithmHandler handler;
    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        handler = new AEMAlgorithmHandler();
        System.setOut(new PrintStream(outContent));
    }

    @Test
    void testEncryptAndDecrypt_ValidAES_AEM() {
        String originalText = "Sensitive data for AES_AEM encryption";

        EncryptionMetadata metadata = new EncryptionMetadata(new EncryptionMetadata.Builder()
                .setAlgorithm("AES_AEM")
                .setMode("GCM")
                .setPadding("NoPadding")
                .setKeySize("256")
                .setKey(""));


        SecretKey key = new KeyBuilder()
                .setAlgorithm("AES")
                .setKeySize(256)
                .build();
        metadata.setKey(Hex.toHexString(key.getEncoded()));


        IntegrityData integrityData = new IntegrityData("", "", "AES");


        String encryptedFileString = handler.encrypt(originalText.getBytes(), metadata, integrityData);
        String[] parts = encryptedFileString.split("\\.");// Split on the first dot
        String encryptedText = parts[1];
        assertNotNull(encryptedText, "Encryption should return a valid encrypted string");
        assertTrue(encryptedText.length() > 10, "Encrypted text should be longer than input text");


        String decryptedText = handler.decrypt(encryptedText, metadata);
        assertNotNull(decryptedText, "Decryption should return a valid string");
        assertEquals(originalText, decryptedText, "Decrypted text should match original text");

        System.out.println("Encrypted AES-AEM Output: " + encryptedText);
        System.out.println("Decrypted AES-AEM Output: " + decryptedText);
    }

    @Test
    void testDecryptWithInvalidCiphertext() {

        String originalText = "Sensitive data for AES_AEM encryption";

        EncryptionMetadata metadata = new EncryptionMetadata(new EncryptionMetadata.Builder()
                .setAlgorithm("AES_AEM")
                .setMode("GCM")
                .setPadding("NoPadding")
                .setKeySize("256")
                .setKey(""));



        SecretKey key = new KeyBuilder()
                .setAlgorithm("AES")
                .setKeySize(256)
                .build();
        metadata.setKey(Hex.toHexString(key.getEncoded()));
        // **Integrity Data**
        IntegrityData integrityData = new IntegrityData("", "", "AES");
        String encryptedFileString = handler.encrypt(originalText.getBytes(), metadata, integrityData);
        String[] parts = encryptedFileString.split("\\.");// Split on the first dot
        String encryptedText = parts[1];
        assertNotNull(encryptedText, "Encryption should return a valid encrypted string");
        assertTrue(encryptedText.length() > 10, "Encrypted text should be longer than input text");


        encryptedText = Hex.toHexString("Sensitive data for AES_AEM encryptio1".getBytes());


        String finalEncryptedText = encryptedText;
        Exception exception = assertThrows(Exception.class, () ->
                handler.decrypt(finalEncryptedText, metadata));

        String consoleOutput = outContent.toString();
        assertTrue(consoleOutput.contains("Bad padding") ||
                        consoleOutput.contains("IllegalBlockSizeException") || consoleOutput.contains("mac check in GCM failed"),
                "Decryption should fail with invalid ciphertext");
    }
}
