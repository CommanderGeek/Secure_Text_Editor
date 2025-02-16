package Factory;

import Handler.*;


/**
 * @author Elias Harb
 * @version 1.0
 * The {@code AlgorithmHandlerFactory} class is responsible for providing the appropriate
 * cryptographic algorithm handler based on the specified encryption algorithm.
 * <p>
 * This factory pattern allows dynamic selection of different encryption algorithms
 * such as AES, ChaCha20, and Password-Based Encryption (PBE).
 * </p>
 *
 * <p><b>Supported Algorithms:</b></p>
 * <ul>
 *   <li>{@code AES_SYM}, {@code AES} → {@link AESAlgorithmHandler}</li>
 *   <li>{@code ChaCha7539}, {@code ChaCha20_SYM}, {@code ChaCha20} → {@link ChaCha20AlgorithmHandler}</li>
 *   <li>{@code AES_AEM} → {@link AEMAlgorithmHandler}</li>
 *   <li>{@code AES_PAS} → {@link PBAESAlgorithmHandler}</li>
 *   <li>{@code ChaCha20_PAS} → {@link PBChaCha20AlgorithmHandler}</li>
 *   <li>{@code PBEWithSHA256And128BitAES-CBC-BC}, {@code PBE_PAS} → {@link PBSHA256AESCBC}</li>
 * </ul>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     CryptoAlgorithmHandler handler = AlgorithmHandlerFactory.getHandler("AES");
 *     String encryptedText = handler.encrypt(plainText, metadata, integrityData);
 * </pre>
 *
 */

public class AlgorithmHandlerFactory {

    /**
     * Returns an instance of the appropriate cryptographic algorithm handler
     * based on the specified algorithm name.
     *
     * @param algorithm The name of the encryption algorithm (e.g., "AES", "ChaCha20").
     * @return An instance of {@link CryptoAlgorithmHandler} that handles the requested algorithm.
     * @throws UnsupportedOperationException if the specified algorithm is not supported.
     */

    public static CryptoAlgorithmHandler getHandler(String algorithm) {
        return switch (algorithm) {
            case "AES_SYM", "AES" -> new AESAlgorithmHandler();
            case "ChaCha7539", "ChaCha20_SYM", "ChaCha20" -> new ChaCha20AlgorithmHandler();
            case "AES_AEM" -> new AEMAlgorithmHandler();
            case "AES_PAS" -> new PBAESAlgorithmHandler();
            case "ChaCha20_PAS" -> new PBChaCha20AlgorithmHandler();
            case "PBEWithSHA256And128BitAES-CBC-BC", "PBE_PAS" -> new PBSHA256AESCBC();
            default -> throw new UnsupportedOperationException("Algorithm not supported");
        };
    }
}