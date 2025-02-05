package com.ste;
import DTOs.EncryptionMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class EncryptionMetadataTest {

    private EncryptionMetadata.Builder builder;

    @BeforeEach
    public void setUp() {
        // Setting up a builder with default values for each test
        builder = new EncryptionMetadata.Builder()
                .setFileId("0af0c20a-55f0-4bed-af35-d656ed601b30")
                .setAlgorithm("AES")
                .setMode("CBC")
                .setPadding("PKCS5Padding")
                .setKeySize("256")
                .setKey("a1b2c3d4e5f6")
                .setIv("1122334455667788")
                .setHash("abc123hash")
                .setEncryptedText("encryptedTextSample");
    }


    @Test
    public void testSetAndGetAlgorithm() {
        EncryptionMetadata metadata = builder.build();
        metadata.setAlgorithm("ChaCha20");

        assertEquals("ChaCha20", metadata.getAlgorithm(), "The algorithm should be updated to ChaCha20");
    }

    @Test
    public void testSetAndGetMode() {
        EncryptionMetadata metadata = builder.build();
        metadata.setMode("GCM");

        assertEquals("GCM", metadata.getMode(), "The mode should be updated to GCM");
    }

    @Test
    public void testSetAndGetPadding() {
        EncryptionMetadata metadata = builder.build();
        metadata.setPadding("NoPadding");

        assertEquals("NoPadding", metadata.getPadding(), "The padding should be updated to NoPadding");
    }

    @Test
    public void testSetAndGetKeySize() {
        EncryptionMetadata metadata = builder.build();
        metadata.setKeySize("128");

        assertEquals("128", metadata.getKeySize(), "The key size should be updated to 128");
    }

    @Test
    public void testSetAndGetKey() {
        EncryptionMetadata metadata = builder.build();
        metadata.setKey("newHexEncodedKey");

        assertEquals("newHexEncodedKey", metadata.getKey(), "The key should be updated to the new value");
    }

    @Test
    public void testSetAndGetIv() {
        EncryptionMetadata metadata = builder.build();
        metadata.setIv("newIvValue");

        assertEquals("newIvValue", metadata.getIv(), "The IV should be updated to the new value");
    }

    @Test
    public void testSetAndGetHash() {
        EncryptionMetadata metadata = builder.build();
        metadata.setIntegrityAlgorithm("newHashValue");

        assertEquals("newHashValue", metadata.getIntegrityAlgorithm(), "The hash should be updated to the new value");
    }

    @Test
    public void testSetAndGetFileId() {
        EncryptionMetadata metadata = builder.build();
        metadata.setFileId("newFileId");

        assertEquals("newFileId", metadata.getFileId(), "The file ID should be updated to the new value");
    }
}