package Handler;

import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import Enums.Const;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
/**
 * @author Elias Harb
 * @version 1.0
 * The {@code ChaCha20AlgorithmHandler} class implements encryption and decryption
 * using the **ChaCha20 stream cipher**.
 * <p>
 * ChaCha20 is a modern cipher that provides **high-speed encryption** and **strong security**.
 * This class ensures proper encryption and decryption while integrating
 * integrity verification mechanisms when required.
 * </p>
 *
 * <p><b>Features:</b></p>
 * <ul>
 *   <li>Implements **ChaCha20 encryption** for high-speed security</li>
 *   <li>Provides decryption and integrity verification support</li>
 *   <li>Handles encryption metadata for algorithm configuration</li>
 * </ul>
 *
 * <p><b>Supported Modes:</b></p>
 * <ul>
 *   <li>**ChaCha20** (Standard ChaCha20 stream cipher mode)</li>
 * </ul>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     ChaCha20AlgorithmHandler handler = new ChaCha20AlgorithmHandler();
 *     String encryptedData = handler.encrypt(plainText, metadata, integrityData);
 *     String decryptedData = handler.decrypt(encryptedData, metadata);
 * </pre>
 *
 */

public class ChaCha20AlgorithmHandler implements CryptoAlgorithmHandler{

    private static final Logger logger = LoggerFactory.getLogger(ChaCha20AlgorithmHandler.class);


    /**
     * Encrypts the provided plaintext using the **ChaCha20 stream cipher**.
     * <p>
     * The encryption process includes:
     * <ul>
     *   <li>Building a ChaCha20 cipher instance</li>
     *   <li>Encrypting the plaintext</li>
     *   <li>Storing encryption metadata (e.g., nonce, key)</li>
     *   <li>Applying integrity protection mechanisms if required</li>
     * </ul>
     *
     * @param plainText The plaintext data to be encrypted as a byte array.
     * @param metadata The encryption metadata containing algorithm parameters.
     * @param data The integrity data containing MAC or signature settings.
     * @return The encrypted ciphertext as a hexadecimal {@link String}.
     */

    @Override
    public String encrypt(byte[] plainText, EncryptionMetadata metadata, IntegrityData data) {
        logger.info("Building Cipher for algorithm: " + Const.ChaCha.getConst());
        Cipher c = service.buildCipher(Const.ChaCha.getConst());
        return service.encryptAndStore(Const.ChaCha.getConst(),c,plainText, metadata, data);
    }

    /**
     * Decrypts the provided ciphertext using the **ChaCha20 stream cipher**.
     * <p>
     * The decryption process includes:
     * <ul>
     *   <li>Building a ChaCha20 cipher instance</li>
     *   <li>Decrypting the ciphertext</li>
     *   <li>Applying integrity verification to detect tampering</li>
     * </ul>
     *
     * @param cipherText The ciphertext to be decrypted as a hexadecimal {@link String}.
     * @param metadata The encryption metadata containing algorithm parameters.
     * @return The decrypted plaintext as a {@link String}.
     */
    @Override
    public String decrypt(String cipherText, EncryptionMetadata metadata) {
        Cipher c = service.buildCipher(metadata.getAlgorithm());
        return service.decrypt(cipherText, c, metadata);
    }

}
