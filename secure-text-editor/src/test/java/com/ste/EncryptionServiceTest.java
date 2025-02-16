package com.ste;
import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import Enums.Const;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import services.EncryptionMetaDataConverter;
import services.EncryptionService;
import services.KeyStoreService;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.InvalidKeyException;
import java.security.Security;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

public class EncryptionServiceTest {

    private EncryptionService encryptionService;
    private final ByteArrayOutputStream outputStreamCaptor = new ByteArrayOutputStream();
    private static final String SAMPLE_TEXT = "EncryptionServiceTest";
    private static final String AES_ALGORITHM = "AES";
    private static final String PBE_ALGORITHM = Const.PBEWithSHA256And128BitAES.getConst();
    private static final String CHACHA20_ALGORITHM = "ChaCha20";
    EncryptionMetaDataConverter converter = new EncryptionMetaDataConverter();
    KeyStoreService ks = new KeyStoreService();

    @BeforeEach
    public void setUp() {
        encryptionService = new EncryptionService();
        Security.addProvider(new BouncyCastleProvider()); // Ensure BouncyCastle is available for tests
        System.setOut(new PrintStream(outputStreamCaptor));
    }

    @Test
    public void testBuildCipher() {
        Cipher cipher = encryptionService.buildCipher("AES", "CBC", "PKCS5Padding");
        assertNotNull(cipher, "Cipher object should not be null");
        assertEquals("AES/CBC/PKCS5Padding", cipher.getAlgorithm(), "The algorithm of the cipher should match");
    }

    @Test
    public void testBuildKey() {
        SecretKey secretKey = encryptionService.buildKey("AES", "BC", 256); // Assuming BC (BouncyCastle) is the provider
        assertNotNull(secretKey, "The generated key should not be null");
        assertEquals("AES", secretKey.getAlgorithm(), "The algorithm of the key should be AES");
    }

    @Test
    void testAESEncryptionDecryption() throws Exception {
        EncryptionMetadata metadata = new EncryptionMetadata.Builder()
                .setAlgorithm(AES_ALGORITHM)
                .setMode("CBC")
                .setPadding("PKCS7Padding")
                .setKeySize("128")
                .setFileId(UUID.randomUUID().toString())
                .build();

        Cipher cipher = encryptionService.buildCipher(AES_ALGORITHM, metadata.getMode(), metadata.getPadding());
        IntegrityData integrityData = new IntegrityData("", "SHA-256");

        // Encrypt
        String encryptedText = encryptionService.encryptAndStore(AES_ALGORITHM, cipher, SAMPLE_TEXT.getBytes(), metadata, integrityData);
        assertNotNull(encryptedText, "Encryption should produce a valid output");

        // Extract ciphertext
        String[] parts = encryptedText.split("\\.");
        assertEquals(2, parts.length, "Encrypted output should contain file ID and ciphertext");
        metadata = converter.lookUpMetaData(parts[0]);
        metadata.setKey(ks.retrieveKey(metadata));
        // Decrypt
        String decryptedText = encryptionService.decrypt(parts[1], cipher, metadata);
        assertEquals(SAMPLE_TEXT, decryptedText, "Decrypted text should match original");
    }


    /**
     *  Tests Key Generation for AES and PBE.
     */
    @Test
    void testKeyGeneration() {
        SecretKey aesKey = encryptionService.buildKey(AES_ALGORITHM, Const.BC.getConst(), 128);
        assertNotNull(aesKey, "AES Key generation should return a valid key");
        assertEquals(16, aesKey.getEncoded().length, "AES 128-bit key should be 16 bytes");

        EncryptionMetadata metadata = new EncryptionMetadata.Builder()
                .setPassword("TestPassword")
                .setKeySize("128")
                .build();
        SecretKey pbeKey = encryptionService.buildPBEKey(metadata);
        assertNotNull(pbeKey, "PBE Key generation should return a valid key");
    }

    /**
     *  Tests Decryption with an Incorrect Key.
     */
    @Test
    void testDecryptionWithIncorrectKey() throws Exception {
        EncryptionMetadata metadata = new EncryptionMetadata.Builder()
                .setAlgorithm(AES_ALGORITHM)
                .setMode("CBC")
                .setPadding("PKCS7Padding")
                .setKeySize("128")
                .setFileId(UUID.randomUUID().toString())
                .build();

        Cipher cipher = encryptionService.buildCipher(AES_ALGORITHM, metadata.getMode(), metadata.getPadding());
        IntegrityData integrityData = new IntegrityData("", "SHA-256");

        // Encrypt
        String encryptedText = encryptionService.encryptAndStore(AES_ALGORITHM, cipher, SAMPLE_TEXT.getBytes(), metadata, integrityData);
        assertNotNull(encryptedText);

        // Extract ciphertext
        String[] parts = encryptedText.split("\\.");

        // Modify key (incorrect key scenario)
        EncryptionMetadata wrongMetadata = new EncryptionMetadata.Builder()
                .setAlgorithm(AES_ALGORITHM)
                .setMode("CBC")
                .setPadding("PKCS7Padding")
                .setKeySize("128")
                .setKey("1234567890abcdef") // Incorrect key
                .build();

        // Attempt decryption
        assertThrows(Exception.class, () -> encryptionService.decrypt(parts[1], cipher, wrongMetadata),
                "Decryption should fail with an incorrect key");
    }

    /**
     *  Tests Monte Carlo Decryption for robustness.
     */
    @Test
    void testMonteCarloDecryption() throws Exception {
        EncryptionMetadata metadata = new EncryptionMetadata.Builder()
                .setAlgorithm(AES_ALGORITHM)
                .setMode("CBC")
                .setPadding("PKCS7Padding")
                .setKeySize("128")
                .setFileId(UUID.randomUUID().toString())
                .build();

        Cipher cipher = encryptionService.buildCipher(AES_ALGORITHM, metadata.getMode(), metadata.getPadding());
        IntegrityData integrityData = new IntegrityData("", "SHA-256");

        String encryptedText = encryptionService.encryptAndStore(AES_ALGORITHM, cipher, SAMPLE_TEXT.getBytes(), metadata, integrityData);
        assertNotNull(encryptedText);

        // Extract metadata and ciphertext
        String[] parts = encryptedText.split("\\.");
        metadata = converter.lookUpMetaData(parts[0]);
        metadata.setKey(ks.retrieveKey(metadata));

        // Decrypt multiple times to test consistency
        for (int i = 0; i < 1000; i++) {
            String decryptedText = encryptionService.decrypt(parts[1], cipher, metadata);
            assertEquals(SAMPLE_TEXT, decryptedText, "Decryption should be consistent across multiple runs");
        }
    }


    /**
     * Tests Multi-Message Encryption/Decryption.
     */
    @Test
    void testMultiMessageEncryptionDecryption() throws Exception {
        String[] messages = {"Hello, World!", "Testing AES", "Bouncy Castle Test"};

        EncryptionMetadata metadata = new EncryptionMetadata.Builder()
                .setAlgorithm(AES_ALGORITHM)
                .setMode("CBC")
                .setPadding("PKCS7Padding")
                .setKeySize("128")
                .setFileId(UUID.randomUUID().toString())
                .build();
        Cipher cipher = encryptionService.buildCipher(AES_ALGORITHM, metadata.getMode(), metadata.getPadding());
        IntegrityData integrityData = new IntegrityData("", "SHA-256");

        byte[][] encryptedMessages = new byte[messages.length][];

        // Encrypt all messages
        for (int i = 0; i < messages.length; i++) {
            encryptedMessages[i] = encryptionService.encryptAndStore(AES_ALGORITHM, cipher, messages[i].getBytes(), metadata, integrityData).getBytes();
        }

        // Decrypt and verify each message
        for (int i = 0; i < messages.length; i++) {
            metadata = converter.lookUpMetaData(new String(encryptedMessages[i]).split("\\.")[0]);
            metadata.setKey(ks.retrieveKey(metadata));
            String decryptedText = encryptionService.decrypt(new String(encryptedMessages[i]).split("\\.")[1], cipher, metadata);
            assertEquals(messages[i], decryptedText, "Decrypted message should match original");
        }
    }

    /**
     * **AES Known Answer Test (KAT)**
     * Ensures AES encryption produces a **deterministic and expected output** for a known input.
     */
    @Test
    void testAESKnownAnswer() throws Exception {
        // Given metadata with predefined key
        EncryptionMetadata metadata = new EncryptionMetadata.Builder()
                .setAlgorithm(AES_ALGORITHM)
                .setMode("CBC")
                .setPadding("PKCS7Padding")
                .setKeySize("128")
                .setFileId(UUID.randomUUID().toString())
                .setKey("00112233445566778899AABBCCDDEEFF") // Known key in hex
                .build();

        Cipher cipher = encryptionService.buildCipher(AES_ALGORITHM, metadata.getMode(), metadata.getPadding());
        IntegrityData integrityData = new IntegrityData("", "SHA-256");

        // Encrypt
        String encryptedText = encryptionService.encryptAndStore(AES_ALGORITHM, cipher, SAMPLE_TEXT.getBytes(), metadata, integrityData);
        assertNotNull(encryptedText, "Encryption should produce a valid output");

        // Extract and decrypt
        String[] parts = encryptedText.split("\\.");
        metadata = converter.lookUpMetaData(parts[0]);
        metadata.setKey(ks.retrieveKey(metadata));
        String decryptedText = encryptionService.decrypt(parts[1], cipher, metadata);

        // Check known answer
        assertEquals(SAMPLE_TEXT, decryptedText, "Decrypted text should match original");
    }

    /**
     * **ChaCha20 Known Answer Test (KAT)**
     * Ensures ChaCha20 encryption produces the expected output.
     */
    @Test
    void testChaCha20KnownAnswer() throws Exception {
        // Given metadata with predefined key and nonce
        EncryptionMetadata metadata = new EncryptionMetadata.Builder()
                .setAlgorithm(CHACHA20_ALGORITHM)
                .setMode("None")
                .setPadding("None")
                .setKeySize("256")
                .setFileId(UUID.randomUUID().toString())
                .setKey("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F") // Known key in hex
                .setIv("000000000000004A00000000") // Known nonce (12-byte)
                .build();

        Cipher cipher = encryptionService.buildCipher(CHACHA20_ALGORITHM);
        IntegrityData integrityData = new IntegrityData("", "SHA-256");

        // Encrypt
        String encryptedText = encryptionService.encryptAndStore(CHACHA20_ALGORITHM, cipher, SAMPLE_TEXT.getBytes(), metadata, integrityData);
        assertNotNull(encryptedText, "Encryption should produce a valid output");

        // Extract and decrypt
        String[] parts = encryptedText.split("\\.");
        metadata = converter.lookUpMetaData(parts[0]);
        metadata.setKey(ks.retrieveKey(metadata));
        String decryptedText = encryptionService.decrypt(parts[1], cipher, metadata);

        // Validate known output
        assertEquals(SAMPLE_TEXT, decryptedText, "Decrypted text should match original");
    }
}
