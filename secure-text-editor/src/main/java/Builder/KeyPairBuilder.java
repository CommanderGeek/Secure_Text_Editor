package Builder;

import Enums.Const;

import java.security.*;

/**
 * @author Elias Harb
 * @version 1.0
 * The {@code KeyPairBuilder} class provides a builder pattern for generating
 * asymmetric key pairs using a specified algorithm and key size.
 * <p>
 * It supports:
 * <ul>
 *   <li>Generating a key pair with a custom algorithm and key size</li>
 *   <li>Generating a key pair with a default key size (3072 bits)</li>
 *   <li>Using a specified security provider (e.g., Bouncy Castle)</li>
 * </ul>
 * </p>
 *
 * <p><b>Example usage:</b></p>
 * <pre>
 *     KeyPair keyPair = new KeyPairBuilder()
 *             .setAlgorithm("DSA")
 *             .setKeySize(3072)
 *             .build();
 * </pre>
 *
 */

public class KeyPairBuilder {
    private String algorithm;
    private int keySize = 3072;

    /**
     * Sets the encryption algorithm for key pair generation.
     *
     * @param algorithm The name of the cryptographic algorithm (e.g., "RSA", "DSA", "EC").
     * @return The current instance of {@code KeyPairBuilder} for method chaining.
     */

    public KeyPairBuilder setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    /**
     * Sets the key size for key pair generation.
     * <p>
     * If not set explicitly, the default key size is 3072 bits.
     * </p>
     *
     * @param keySize The size of the key in bits (e.g., 2048, 3072, 4096).
     * @return The current instance of {@code KeyPairBuilder} for method chaining.
     */
    public KeyPairBuilder setKeySize(int keySize) {
        this.keySize = keySize;
        return this;
    }


    /**
     * Builds and returns a {@link KeyPair} instance using the specified algorithm
     * and key size.
     * <p>
     * This method ensures that the key size is explicitly set before generating the key pair.
     * </p>
     *
     * @return A {@link KeyPair} instance.
     * @throws RuntimeException If the algorithm or provider is not available.
     */
    public KeyPair build() {
        try {
            KeyPairGenerator keyPair = KeyPairGenerator.getInstance(algorithm, new org.bouncycastle.jce.provider.BouncyCastleProvider());
            keyPair.initialize(keySize);
            return keyPair.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Builds and returns a {@link KeyPair} instance using the specified algorithm
     * with the provider's default key size.
     * <p>
     * This method does not explicitly set a key size and instead relies on
     * the default size provided by the cryptographic provider.
     * </p>
     *
     * @return A {@link KeyPair} instance.
     * @throws RuntimeException If the algorithm or provider is not available.
     */
    public KeyPair buildNoSize()  {
        KeyPairGenerator keyPair = null;
        try {
            keyPair = KeyPairGenerator.getInstance(algorithm, Const.BC.getConst());
            return keyPair.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }
}
