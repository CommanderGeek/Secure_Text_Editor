package com.ste;
import Builder.CipherBuilder;
import Enums.Const;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

class CipherBuilderTest {

    private CipherBuilder cipherBuilder;

    @BeforeEach
    void setUp() {
        cipherBuilder = new CipherBuilder();
        Security.addProvider(new BouncyCastleProvider()); // Ensure BouncyCastle is registered
    }

    @Test
    void testBuildCipherWithValidParameters() {
        Cipher cipher = cipherBuilder
                .setAlgorithm("AES")
                .setMode("GCM")
                .setPadding("NoPadding")
                .build();

        assertNotNull(cipher, "Cipher should be created successfully");
        assertEquals("AES/GCM/NoPadding", cipher.getAlgorithm(), "Cipher algorithm should match input");
    }

    @Test
    void testBuildCipherWithInvalidAlgorithm() {
        Cipher cipher = cipherBuilder
                .setAlgorithm("INVALID")
                .setMode("GCM")
                .setPadding("NoPadding")
                .build();

        assertNull(cipher, "Cipher should return null for invalid algorithm");
    }

    @Test
    void testBuildCipherWithInvalidMode() {
        Cipher cipher = cipherBuilder
                .setAlgorithm("AES")
                .setMode("INVALID_MODE")
                .setPadding("NoPadding")
                .build();

        assertNull(cipher, "Cipher should return null for invalid mode");
    }

    @Test
    void testBuildCipherWithInvalidPadding() {
        Cipher cipher = cipherBuilder
                .setAlgorithm("AES")
                .setMode("CBC")
                .setPadding("InvalidPadding")
                .build();

        assertNull(cipher, "Cipher should return null for invalid padding");
    }

    @Test
    void testBuildCipherWithoutMode() {
        Cipher cipher = cipherBuilder
                .setAlgorithm("AES")
                .setPadding("PKCS5Padding")
                .build();

        assertNull(cipher, "Cipher should return null if mode is missing");
    }

    @Test
    void testBuildCipherWithoutPadding() {
        Cipher cipher = cipherBuilder
                .setAlgorithm("AES")
                .setMode("GCM")
                .build();

        assertNull(cipher, "Cipher should return null if padding is missing");
    }

    @Test
    void testBuildCipherWithDirectAlgorithmOnly() {
        Cipher cipher = cipherBuilder.build("AES");

        assertNotNull(cipher, "Cipher should be created when only algorithm is provided");
        assertEquals("AES", cipher.getAlgorithm(), "Cipher algorithm should be AES");
    }

    @Test
    void testBuildCipherWithInvalidAlgorithmDirectly() {
        Cipher cipher = cipherBuilder.build("INVALID_ALGO");

        assertNull(cipher, "Cipher should return null for invalid direct algorithm input");
    }

    @Test
    void testBouncyCastleProviderIsRegistered() throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", Const.BC.getConst());
        assertNotNull(cipher, "Cipher instance should be created with BouncyCastle provider");
    }
}