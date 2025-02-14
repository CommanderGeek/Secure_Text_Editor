package com.ste;

import Builder.KeyPairBuilder;
import Enums.Const;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.Security;

import static junit.framework.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.*;

class KeyPairBuilderTest {

    private KeyPairBuilder keyPairBuilder;

    @BeforeEach
    void setUp() {
        keyPairBuilder = new KeyPairBuilder();
        Security.addProvider(new BouncyCastleProvider()); // Ensure BouncyCastle is registered
    }

    @Test
    void testBuildKeyPairWithValidAlgorithm() {
        KeyPair keyPair = keyPairBuilder
                .setAlgorithm("RSA")
                .build();

        assertNotNull(keyPair, "KeyPair should be generated successfully");
        assertNotNull(keyPair.getPublic(), "Public key should not be null");
        assertNotNull(keyPair.getPrivate(), "Private key should not be null");
    }


    @Test
    void testBuildKeyPairWitheEd448() {
        KeyPair keyPair = keyPairBuilder
                .setAlgorithm("Ed448")
                .buildNoSize();

        assertNotNull(keyPair, "KeyPair should be generated successfully for Ed448");
        assertEquals("Algorithm should match Ed448", keyPair.getPrivate().getAlgorithm(), "Ed448");
    }

    @Test
    void testBuildKeyPairWithInvalidAlgorithm() {
        Exception exception = assertThrows(RuntimeException.class, () ->
                keyPairBuilder.setAlgorithm("INVALID_ALGO").build());

        assertTrue(exception.getCause() instanceof java.security.NoSuchAlgorithmException,
                "Exception should be caused by NoSuchAlgorithmException");
    }


    @Test
    void testBouncyCastleProviderIsRegistered() {
        assertNotNull(Security.getProvider(Const.BC.getConst()), "Bouncy Castle provider should be registered");
    }
}