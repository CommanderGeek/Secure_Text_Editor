package com.ste;

import DTOs.DecryptPBERequest;
import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import Factory.AlgorithmHandlerFactory;
import Handler.SHA256Handler;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import services.EncryptionMetaDataConverter;
import services.EncryptionService;
import services.KeyStoreService;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

class DecryptionTest {

    private Decryption decryption;
    private EncryptionService encryptionService;

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        decryption = new Decryption();
        encryptionService = new EncryptionService();
    }

    @Test
    void testDecryptAES_CBC_Valid() throws Exception {
        // **Test Data for AES (CBC)**
        String encryptedTextWithId = "8b2c965c-dc7f-4e23-9d53-58a02e71f09b.34623062623932353238626433333465613434396461376634373537356335373463363466656536346562303435343666316537363364366265636336393237";

        // **Metadata matching AES Encryption**
        EncryptionMetadata metadata = new EncryptionMetadata(new EncryptionMetadata.Builder()
                .setFileId("8b2c965c-dc7f-4e23-9d53-58a02e71f09b")
                .setAlgorithm("AES")
                .setMode("CBC")
                .setPadding("PKCS7Padding")
                .setKeySize("128")
                .setIv("b04d991387fb69384b11554c5228e65a")
        );
        // **Retrieve Key**
        metadata.setKey(generateTestKey(metadata.getAlgorithm(), Integer.parseInt(metadata.getKeySize())));

        // **Run Decryption**
        String decryptedText = decryption.decryptText(encryptedTextWithId);

        // **Validate Output**
        assertNotNull(decryptedText, "Decryption should return a valid string");
        System.out.println("Decrypted AES-CBC Text: " + decryptedText);
    }

    @Test
    void testDecryptPBE_Valid() {
        // **Test Data for PBE**
        String encryptedPBE = "49265cb6-20da-43a9-b197-aa82333acba9.8057ab9da1384ff1bbf84e6e458e5416";

        // **Prepare PBE Decryption Request**
        DecryptPBERequest request = new DecryptPBERequest();
        request.setText(encryptedPBE);
        request.setPassword("mySecurePassword");

        // **Metadata for PBE**
        EncryptionMetadata metadata = new EncryptionMetadata(new EncryptionMetadata.Builder()
                .setFileId("49265cb6-20da-43a9-b197-aa82333acba9")
                .setAlgorithm("PBE_PAS")
                .setPassword(request.getPassword()));

        // **Derive Key**
        SecretKey derivedKey = encryptionService.buildPBEKey(metadata);
        metadata.setKey(Hex.toHexString(derivedKey.getEncoded()));

        // **Run Decryption**
        String decryptedText = decryption.decryptPBE(request);

        // **Validate Output**
        assertNotNull(decryptedText, "Decryption should return a valid string");
        System.out.println("Decrypted PBE Text: " + decryptedText);
    }

    @Test
    void testDecryptPBE_WrongPassword() {
        // **Encrypted Data**
        String encryptedPBE = "49265cb6-20da-43a9-b197-aa82333acba9.8057ab9da1384ff1bbf84e6e458e5416";

        // **Prepare PBE Request with Wrong Password**
        DecryptPBERequest request = new DecryptPBERequest();
        request.setText(encryptedPBE);
        request.setPassword("wrongPassword");

        EncryptionMetadata metadata = new EncryptionMetadata(new EncryptionMetadata.Builder()
                .setFileId("49265cb6-20da-43a9-b197-aa82333acba9")
                .setAlgorithm("PBE_PAS")
                .setPassword(request.getPassword()));


        String result = decryption.decryptPBE(request);


        assertEquals("WRONG PASSWORD!", result);
    }

    @Test
    void testDecryptPBE_PasswordCompromised() {

        String tamperedEncryptedPBE = "49265cb6-20da-43a9-b197-aa82333acba9.1234abcd5678";


        DecryptPBERequest request = new DecryptPBERequest();
        request.setText(tamperedEncryptedPBE);
        request.setPassword("mySecurePassword");

        EncryptionMetadata metadata = new EncryptionMetadata(new EncryptionMetadata.Builder()
                .setFileId("49265cb6-20da-43a9-b197-aa82333acba9")
                .setAlgorithm("PBE_PAS")
                .setPassword(request.getPassword()));

        // **Run Decryption**
        String result = decryption.decryptPBE(request);

        // **Expect Message Integrity Failure**
        assertEquals("WRONG PASSWORD!", result);
    }

    @Test
    void testDecryptAES_CBC_InvalidIV() throws Exception {
        // **Tampered AES String**
        String encryptedTextWithId = "8b2c965c-dc7f-4e23-9d53-58a02e71f09b.34623062623932353238626433333465613434396461376634373537356335373463363466656536346562303435343666316537363364366265636336393237";

        // **Metadata with Incorrect IV**
        EncryptionMetadata metadata = new EncryptionMetadata(new EncryptionMetadata.Builder()
                .setFileId("8b2c965c-dc7f-4e23-9d53-58a02e71f09b")
                .setAlgorithm("AES")
                .setMode("CBC")
                .setPadding("PKCS7Padding")
                .setKeySize("128")
                .setIv("00000000000000000000000000000000")
        );


        metadata.setKey(generateTestKey("AES", 128));

        Exception exception = assertThrows(Exception.class, () ->
                decryption.decryptText(encryptedTextWithId));

        // **Expect an error due to invalid IV**
        assertTrue(exception.getMessage().contains("BadPaddingException"), "Decryption should fail due to incorrect IV");
    }

    /**
     * **Generates a temporary test AES key (hex-encoded)**
     * @param algorithm Algorithm type (AES, etc.)
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
