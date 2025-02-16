package Builder;

import javax.crypto.Mac;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


/**
 * @author Elias Harb
 * @version 1.0
 * The {@code MacBuilder} class provides a builder pattern for creating
 * Message Authentication Code (MAC) instances using a specified hashing algorithm.
 * <p>
 * It supports:
 * <ul>
 *   <li>Generating a MAC instance using a specified hash algorithm</li>
 *   <li>Using the Bouncy Castle ("BC") provider for cryptographic operations</li>
 * </ul>
 * </p>
 *
 * <p><b>Example usage:</b></p>
 * <pre>
 *     Mac mac = new MacBuilder("HmacSHA256").build();
 * </pre>
 *
 */

public class MacBuilder {
    private String hash;

    /**
     * Constructs a {@code MacBuilder} with the specified hashing algorithm.
     *
     * @param hash The name of the MAC algorithm (e.g., "HmacSHA256", "HmacSHA512").
     */
    public MacBuilder(String hash){
        setHash(hash);
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    /**
     * Builds and returns a {@link Mac} instance using the specified hash algorithm.
     * <p>
     * This method uses the Bouncy Castle provider ("BC"). If the algorithm or provider
     * is not found, a {@link RuntimeException} is thrown.
     * </p>
     *
     * @return A {@link Mac} instance initialized with the specified hash algorithm.
     * @throws RuntimeException If the algorithm or provider is not available.
     */
    public Mac build(){
        try {
            return Mac.getInstance(getHash(), "BC");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Mac Algorithm does not exist");
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }
}
