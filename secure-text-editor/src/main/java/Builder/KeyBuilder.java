package Builder;

import Enums.Const;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;


/**
 * @author Elias Harb
 * @version 1.0
 * The {@code KeyBuilder} class provides a builder pattern for generating
 * cryptographic keys based on the specified algorithm, provider, and key size.
 * <p>
 * It supports:
 * <ul>
 *   <li>Generating a new key using a specified algorithm and key size</li>
 *   <li>Constructing a key from an existing byte array</li>
 *   <li>Using a specified security provider (e.g., Bouncy Castle)</li>
 * </ul>
 * </p>
 *
 * <p><b>Example usage:</b></p>
 * <pre>
 *     SecretKey secretKey = new KeyBuilder()
 *             .setAlgorithm("AES")
 *             .setKeySize(256)
 *             .build();
 * </pre>
 *
 */

public class KeyBuilder {

    private String algorithm;
    private String provider;
    private int keySize;
    private byte[] key;


    /**
     * Sets the encryption algorithm for key generation.
     *
     * @param algorithm The name of the cryptographic algorithm (e.g., "AES", "DES").
     * @return The current instance of {@code KeyBuilder} for method chaining.
     */
    public KeyBuilder setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    /**
     * Sets the security provider for key generation.
     *
     * @param provider The name of the security provider (e.g., "BC" for Bouncy Castle).
     * @return The current instance of {@code KeyBuilder} for method chaining.
     */
    public KeyBuilder setProvider(String provider) {
        this.provider = provider;
        return this;
    }

    /**
     * Sets the key size for key generation.
     *
     * @param keySize The size of the key in bits (e.g., 128, 192, 256).
     * @return The current instance of {@code KeyBuilder} for method chaining.
     */
    public KeyBuilder setKeySize(int keySize) {
        this.keySize = keySize;
        return this;
    }

    /**
     * Sets a pre-existing key to be used instead of generating a new one.
     *
     * @param key The byte array representing the key.
     * @return The current instance of {@code KeyBuilder} for method chaining.
     */
    public KeyBuilder setKey(byte[] key) {
        this.key = key;
        return this;
    }


    /**
     * Builds and returns a {@link SecretKey} instance based on the provided configuration.
     * <p>
     * This method either:
     * <ul>
     *   <li>Creates a {@link SecretKeySpec} from a provided key with algorithm</li>
     *   <li>Generates a new key using the specified algorithm and key size</li>
     * </ul>
     * </p>
     *
     *
     * @return A {@link SecretKey} instance
     */

    public SecretKey build() {
        try {
            if(key != null && algorithm != null) {
                return  new SecretKeySpec(key,algorithm);
            }else if (algorithm != null && keySize > 0) {
                KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm, Const.BC.getConst());
                keyGenerator.init(keySize);
            return keyGenerator.generateKey();
            }
        }catch (NoSuchAlgorithmException e){
            System.out.println("The given Algorithm does not exists. Check the String input with setAlgorithm! ");
            System.out.println("-------------------------------");
            e.printStackTrace();
        }catch (NoSuchProviderException e){
            System.out.println("Bouncy Castle is not available? Check if the dependency is set in pom.xml!");
            System.out.println("-------------------------------");
            System.out.println("Provider not ");
            e.printStackTrace();
        }
        return null;
    }



}
