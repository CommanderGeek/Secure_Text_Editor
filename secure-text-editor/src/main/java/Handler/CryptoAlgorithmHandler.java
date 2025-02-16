package Handler;

import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import services.EncryptionService;


/**
 * @author Elias Harb
 * @version 1.0
 *
 * The {@code CryptoAlgorithmHandler} interface defines the standard contract
 * for implementing cryptographic encryption and decryption handlers.
 * <p>
 * Each cryptographic algorithm handler (e.g., AES, ChaCha20, PBE) must implement
 * this interface to provide **encryption** and **decryption** functionalities.
 * </p>
 *
 * <p><b>Responsibilities:</b></p>
 * <ul>
 *   <li>Defines a method for encrypting plaintext data.</li>
 *   <li>Defines a method for decrypting ciphertext data.</li>
 *   <li>Uses {@link EncryptionService} to perform cryptographic operations.</li>
 * </ul>
 *
 * <p><b>Implementing Classes:</b></p>
 * <ul>
 *   <li>{@link AESAlgorithmHandler}</li>
 *   <li>{@link ChaCha20AlgorithmHandler}</li>
 *   <li>{@link AEMAlgorithmHandler}</li>
 *   <li>{@link PBAESAlgorithmHandler}</li>
 *   <li>{@link PBChaCha20AlgorithmHandler}</li>
 *   <li>{@link PBSHA256AESCBC}</li>
 * </ul>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     CryptoAlgorithmHandler handler = new AESAlgorithmHandler();
 *     String encryptedData = handler.encrypt(plainText, metadata, integrityData);
 *     String decryptedData = handler.decrypt(encryptedData, metadata);
 * </pre>
 *
 */

public interface CryptoAlgorithmHandler {
    EncryptionService service = new EncryptionService();
    /**
     * Encrypts the given plaintext using the specified encryption algorithm.
     *
     * @param plainText The plaintext data to be encrypted as a byte array.
     * @param metadata The encryption metadata containing algorithm parameters.
     * @param data The integrity data containing MAC or signature settings.
     * @return The encrypted ciphertext as a hexadecimal {@link String}.
     */
    String encrypt(byte[] plainText, EncryptionMetadata metadata, IntegrityData data);

    /**
     * Decrypts the given ciphertext using the specified encryption algorithm.
     *
     * @param cipherText The ciphertext to be decrypted as a hexadecimal {@link String}.
     * @param metadata The encryption metadata containing algorithm parameters.
     * @return The decrypted plaintext as a {@link String}.
     */
    String decrypt(String cipherText, EncryptionMetadata metadata);
}

