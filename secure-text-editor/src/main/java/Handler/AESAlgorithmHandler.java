package Handler;

import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import Enums.Const;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;

/**
 * @author Elias Harb
 * @version 1.0
 * The {@code AESAlgorithmHandler} class provides an implementation
 * for **AES (Advanced Encryption Standard) encryption and decryption**.
 * <p>
 * This handler supports **AES encryption in different modes**, such as:
 * <ul>
 *   <li>CBC (Cipher Block Chaining)</li>
 *   <li>GCM (Galois/Counter Mode)</li>
 *   <li>OFB (Output Feedback Mode)</li>
 *   <li>CTR (Counter Mode)</li>
 *   <li>CFB (Cipher Feedback Mode)</li>
 * </ul>
 * </p>
 *
 * <p><b>Features:</b></p>
 * <ul>
 *   <li>Encrypts plaintext using AES block cipher with configurable modes and padding</li>
 *   <li>Decrypts ciphertext while applying integrity protection</li>
 *   <li>Supports AES key sizes (128, 192, 256-bit)</li>
 *   <li>Integrates integrity protection mechanisms (e.g., MAC or digital signatures)</li>
 * </ul>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     AESAlgorithmHandler handler = new AESAlgorithmHandler();
 *     String encryptedData = handler.encrypt(plainText, metadata, integrityData);
 *     String decryptedData = handler.decrypt(encryptedData, metadata);
 * </pre>
 *
 */

public class AESAlgorithmHandler implements CryptoAlgorithmHandler{

    private static final Logger logger = LoggerFactory.getLogger(AESAlgorithmHandler.class);

    /**
     * Encrypts the provided plaintext using AES encryption.
     * <p>
     * The encryption process includes:
     * <ul>
     *   <li>Generating an AES cipher with the specified mode and padding</li>
     *   <li>Applying AES encryption using the provided key</li>
     *   <li>Storing encryption metadata (e.g., IV, authentication tag)</li>
     *   <li>Applying integrity protection mechanisms (e.g., MAC or digital signatures)</li>
     * </ul>
     *
     * @param plainText The plaintext data to be encrypted as a byte array.
     * @param metadata The encryption metadata containing algorithm parameters.
     * @param data The integrity data containing MAC or signature settings.
     * @return The encrypted ciphertext as a hexadecimal {@link String}.
     */

    @Override
    public String encrypt(byte[] plainText, EncryptionMetadata metadata, IntegrityData data) {

        Cipher c = service.buildCipher(Const.AES.getConst(), metadata.getMode(), metadata.getPadding());
        return service.encryptAndStore(Const.AES.getConst(), c, plainText, metadata, data);
    }

    /**
     * Decrypts the provided ciphertext using AES decryption.
     * <p>
     * The decryption process includes:
     * <ul>
     *   <li>Generating an AES cipher with the specified mode and padding</li>
     *   <li>Applying AES decryption using the provided key</li>
     *   <li>Verifying integrity (if MAC/signature is enabled)</li>
     * </ul>
     *
     * @param cipherText The ciphertext to be decrypted as a hexadecimal {@link String}.
     * @param metadata The encryption metadata containing algorithm parameters.
     * @return The decrypted plaintext as a {@link String}.
     */
    @Override
    public String decrypt(String cipherText, EncryptionMetadata metadata) {
        Cipher c = service.buildCipher(metadata.getAlgorithm(), metadata.getMode(), metadata.getPadding());
        return service.decrypt(cipherText, c, metadata);
    }
}
