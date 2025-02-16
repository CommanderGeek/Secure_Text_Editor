package Handler;

import Builder.KeyBuilder;
import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import Enums.Const;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Objects;

/**
 * @author Elias Harb
 * @version 1.0
 *
 * The {@code AEMAlgorithmHandler} class provides an implementation
 * of the AES-based Authenticated Encryption Mode (AEM).
 * <p>
 * AEM ensures both **confidentiality and authentication** of encrypted data.
 * This handler is responsible for performing encryption and decryption
 * using AES with an authenticated mode, supporting **integrity checks** via MAC or signatures.
 * </p>
 *
 * <p><b>Features:</b></p>
 * <ul>
 *   <li>Encrypts plaintext using AES-based authenticated encryption</li>
 *   <li>Decrypts ciphertext while verifying integrity</li>
 *   <li>Supports AES block cipher with multiple modes (e.g., GCM, CCM, CBC)</li>
 *   <li>Handles encryption metadata for consistency</li>
 * </ul>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     AEMAlgorithmHandler handler = new AEMAlgorithmHandler();
 *     String encryptedData = handler.encrypt(plainText, metadata, integrityData);
 *     String decryptedData = handler.decrypt(encryptedData, metadata);
 * </pre>
 *
 */

public class AEMAlgorithmHandler implements CryptoAlgorithmHandler {
    private static final Logger logger = LoggerFactory.getLogger(AEMAlgorithmHandler.class);

    /**
     * Encrypts the provided plaintext using AES with an authenticated encryption mode.
     * <p>
     * The encryption process includes:
     * <ul>
     *   <li>Generating a cipher based on AES with the specified mode and padding</li>
     *   <li>Storing encryption metadata (e.g., key, IV, authentication tag)</li>
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
     * Decrypts the provided ciphertext using AES authenticated encryption.
     * <p>
     * The decryption process includes:
     * <ul>
     *   <li>Generating a cipher based on AES with the specified mode and padding</li>
     *   <li>Applying integrity verification to detect tampering</li>
     *   <li>Returning the decrypted plaintext if verification is successful</li>
     * </ul>
     *
     * @param cipherText The ciphertext to be decrypted as a hexadecimal {@link String}.
     * @param metadata The encryption metadata containing algorithm parameters.
     * @return The decrypted plaintext as a {@link String}.
     */

    @Override
    public String decrypt(String cipherText, EncryptionMetadata metadata) {
        Cipher c = service.buildCipher(Const.AES.getConst(), metadata.getMode(), metadata.getPadding());
        return service.decrypt(cipherText, c, metadata);
    }
}
