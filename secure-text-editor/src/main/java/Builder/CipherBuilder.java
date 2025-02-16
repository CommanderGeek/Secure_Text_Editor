package Builder;

import Enums.Const;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

/**
 * @author Elias Harb
 * @version 1.0
 *
 * The {@code CipherBuilder} class provides a builder pattern for constructing a
 * {@link Cipher} instance with a specified encryption algorithm, mode, and padding scheme.
 * It ensures that the Bouncy Castle provider is used for cryptographic operations.
 * <p>
 * Example usage:
 * <pre>
 *     Cipher cipher = new CipherBuilder()
 *             .setAlgorithm("AES")
 *             .setMode("CBC")
 *             .setPadding("PKCS5Padding")
 *             .build();
 * </pre>
 * </p>
 *
 *
 */

public class CipherBuilder {

    private String algo;
    private String mode;
    private String padding;

    public CipherBuilder setAlgorithm(String algo) {
        this.algo = algo;
        return this;
    }

    public CipherBuilder setMode(String mode){
        this.mode = mode;
        return this;
    }

    public CipherBuilder setPadding(String padding){
        this.padding = padding;
        return this;
    }


    /**
     * Builds and returns a {@link Cipher} instance configured with the specified
     * algorithm, mode, and padding scheme.
     * <p>
     * The method adds the Bouncy Castle security provider before creating the cipher.
     * If any of the required parameters (algorithm, mode, or padding) are missing, it returns {@code null}.
     * </p>
     *
     * @return A configured {@link Cipher} instance, or {@code null} if an error occurs.
     */
    public Cipher build() {
        try {
            if (algo != null && mode != null && padding != null) {
                Security.addProvider(new BouncyCastleProvider());
                String input = algo + "/" + mode + "/" + padding;
                return Cipher.getInstance(input, Const.BC.getConst());
            }
        }catch (NoSuchPaddingException e){
            System.out.println("The given Padding does not exists. Check the String input with setPadding! ");
            System.out.println("-------------------------------");
            e.printStackTrace();
        }catch (NoSuchAlgorithmException e){
            System.out.println("The given Algorithm does not exists. Check the String input with setAlgorithm! ");
            System.out.println("-------------------------------");
            e.printStackTrace();
        }catch (NoSuchProviderException e){
            System.out.println("Bouncy Castle is not available? Check if the dependency is set in pom.xml!");
            System.out.println("-------------------------------");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Builds and returns a {@link Cipher} instance with the specified algorithm
     * using the default Bouncy Castle provider.
     * <p>
     * This method is useful when only the algorithm is known, like in ChaCha20 case.
     * </p>
     *
     * @param algo The encryption algorithm (e.g., "AES").
     * @return A configured {@link Cipher} instance, or {@code null} if an error occurs.
     */
    public Cipher build(String algo){
        try {
            if (algo != null) {
                Security.addProvider(new BouncyCastleProvider());
                String provider = "BC";
                return Cipher.getInstance(algo, provider);
            }
        }catch (NoSuchPaddingException e){
            System.out.println("The given Padding does not exists. Check the String input with setPadding! ");
            System.out.println("-------------------------------");
            e.printStackTrace();
        }catch (NoSuchAlgorithmException e){
            System.out.println("The given Algorithm does not exists. Check the String input with setAlgorithm! ");
            System.out.println("-------------------------------");
            e.printStackTrace();
        }catch (NoSuchProviderException e){
            System.out.println("Bouncy Castle is not available? Check if the dependency is set in pom.xml!");
            System.out.println("-------------------------------");
            e.printStackTrace();
        }
        return null;
    }

}
