package Factory;

import Handler.*;


/**
 * @author Elias Harb
 * @version 1.0
 * The {@code IntegrityHandlerFactory} class provides an appropriate integrity handler
 * based on the specified hashing or authentication algorithm.
 * <p>
 * This factory allows dynamic selection of different integrity mechanisms,
 * including hash-based message authentication codes (HMAC), cipher-based MACs (CMAC),
 * and digital signatures.
 * </p>
 *
 * <p><b>Supported Integrity Algorithms:</b></p>
 * <ul>
 *   <li>{@code SHA-256} → {@link SHA256Handler}</li>
 *   <li>{@code AESCMAC} → {@link AESCMACHandler}</li>
 *   <li>{@code HMACSHA256} → {@link HMACSHA256Handler}</li>
 *   <li>{@code SHA256withDSA} → {@link SHA256DSAHandler}</li>
 * </ul>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     IntegrityHandler handler = IntegrityHandlerFactory.getHandler("SHA-256");
 *     String hash = handler.compute(data, metadata);
 *     boolean isValid = handler.verify(data, metadata);
 * </pre>
 *
 */
public class IntegrityHandlerFactory {

    /**
     * Returns an instance of the appropriate integrity handler based on the specified algorithm.
     *
     * @param algorithm The name of the integrity algorithm (e.g., "SHA-256", "HMACSHA256").
     * @return An instance of {@link IntegrityHandler} that handles the requested algorithm.
     * @throws UnsupportedOperationException if the specified algorithm is not supported.
     */
    public static IntegrityHandler getHandler(String algorithm) {
        return switch (algorithm) {
            case "SHA-256" -> new SHA256Handler();
            case "AESCMAC" -> new AESCMACHandler();
            case "HMACSHA256" -> new HMACSHA256Handler();
            case "SHA256withDSA" -> new SHA256DSAHandler();
            default -> throw new UnsupportedOperationException("Algorithm not supported");
        };
    }
}
