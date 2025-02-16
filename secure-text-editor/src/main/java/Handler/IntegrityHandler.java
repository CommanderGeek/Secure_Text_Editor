package Handler;

import DTOs.EncryptionMetadata;

/**
 * @author Elias Harb
 * @version 1.0
 * The {@code IntegrityHandler} interface defines the contract for implementing
 * cryptographic integrity protection mechanisms.
 * <p>
 * Each integrity handler (e.g., HMAC, CMAC, Digital Signatures) must implement
 * this interface to provide **hash-based integrity verification**.
 * </p>
 *
 * <p><b>Responsibilities:</b></p>
 * <ul>
 *   <li>Defines a method for computing integrity hashes (e.g., HMAC, CMAC).</li>
 *   <li>Defines a method for verifying the integrity of plaintext data.</li>
 *   <li>Uses {@link EncryptionMetadata} to access relevant cryptographic parameters.</li>
 * </ul>
 *
 * <p><b>Implementing Classes:</b></p>
 * <ul>
 *   <li>{@link HMACSHA256Handler} - Computes and verifies **HMAC-SHA256** hashes.</li>
 *   <li>{@link AESCMACHandler} - Computes and verifies **AES-CMAC** hashes.</li>
 *   <li>{@link SHA256DSAHandler} - Computes and verifies **DSA digital signatures**.</li>
 * </ul>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     IntegrityHandler handler = new HMACSHA256Handler();
 *     String hashValue = handler.compute(plainText, metadata);
 *     boolean isValid = handler.verify(plainText, metadata);
 * </pre>
 *
 */
public interface IntegrityHandler {

    /**
     * Computes an integrity-protecting hash for the given plaintext.
     * <p>
     * This method generates a cryptographic integrity check (e.g., HMAC, CMAC)
     * using a secret key or other cryptographic parameters stored in {@link EncryptionMetadata}.
     * </p>
     *
     * @param plainText The plaintext data for which the integrity hash is computed.
     * @param metadata The encryption metadata containing relevant cryptographic parameters.
     * @return The computed integrity hash as a hexadecimal {@link String}.
     */
    String compute(byte[] plainText, EncryptionMetadata metadata);

    /**
     * Verifies the integrity of a given plaintext by comparing its computed hash
     * with the stored hash in metadata.
     * <p>
     * The verification process includes:
     * <ul>
     *   <li>Computing the hash of the input text</li>
     *   <li>Decoding the stored hash from metadata</li>
     *   <li>Securely comparing the computed and stored hashes</li>
     * </ul>
     *
     * @param plainText The plaintext data to verify.
     * @param metadata The encryption metadata containing the stored hash.
     * @return {@code true} if the computed and stored hashes match, {@code false} otherwise.
     */
    boolean verify(byte[] plainText, EncryptionMetadata metadata);
}
