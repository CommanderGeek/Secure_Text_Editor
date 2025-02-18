package com.ste;

import Builder.KeyBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

public class KeyBuilderTest {

    private KeyBuilder keyBuilder;


    @BeforeEach
    void setUp() {
        keyBuilder = new KeyBuilder();
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void testBuildKeyWithValidAlgorithmProviderAndKeySize() {
        SecretKey secretKey = keyBuilder
                .setAlgorithm("AES")
                .setProvider("BC")
                .setKeySize(256)
                .build();

        assertNotNull(secretKey, "SecretKey should be created successfully");
        assertEquals("AES", secretKey.getAlgorithm(), "Algorithm should match AES");
        assertEquals(32, secretKey.getEncoded().length, "Key size should be 256 bits (32 bytes)");
    }

    @Test
    void testBouncyCastleProviderIsRegistered() {
        assertNotNull(Security.getProvider("BC"), "Bouncy Castle provider should be registered");
    }
}
