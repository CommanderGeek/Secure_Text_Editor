package Handler;

import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import Enums.Const;
import org.bouncycastle.util.encoders.Hex;

/**
 * @author Elias Harb
 * @version 1.0
 * The {@code PBChaCha20AlgorithmHandler} class provides an implementation for **Password-Based Encryption (PBE)**
 * using the **ChaCha20** cipher.
 * <p>
 * This handler derives a cryptographic key from a password using the **Scrypt key derivation function**.
 * It then encrypts or decrypts data using ChaCha20, delegating to {@link ChaCha20AlgorithmHandler} for encryption.
 * </p>
 *
 * <p><b>Features:</b></p>
 * <ul>
 *   <li>Uses **Scrypt key derivation** to generate a secure key.</li>
 *   <li>Supports encryption using the **ChaCha20** cipher.</li>
 *   <li>Prefixes ciphertext with a **PBE marker** to indicate password-based encryption.</li>
 *   <li>Delegates decryption to {@link PBAESAlgorithmHandler}.</li>
 * </ul>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     PBChaCha20AlgorithmHandler handler = new PBChaCha20AlgorithmHandler();
 *     String encryptedData = handler.encrypt(plainText, metadata, integrityData);
 *     String decryptedData = handler.decrypt(encryptedData, metadata);
 * </pre>
 *
 */
public class PBChaCha20AlgorithmHandler implements CryptoAlgorithmHandler {

    /**
     * Encrypts the given plaintext using **ChaCha20 Password-Based Encryption (PBE)**.
     * <p>
     * The encryption process includes:
     * <ul>
     *   <li>Deriving a cryptographic key from the password using **Scrypt**.</li>
     *   <li>Storing the derived key in metadata (Hex-encoded).</li>
     *   <li>Encrypting the plaintext using **ChaCha20** via {@link ChaCha20AlgorithmHandler}.</li>
     *   <li>Prefixing the ciphertext with a **PBE marker**.</li>
     * </ul>
     *
     * @param plainText The plaintext data to be encrypted.
     * @param metadata The encryption metadata containing algorithm parameters.
     * @param data The integrity data containing MAC or signature settings.
     * @return The encrypted ciphertext as a **PBE-prefixed hexadecimal string**.
     */
    @Override
    public String encrypt(byte[] plainText, EncryptionMetadata metadata, IntegrityData data) {
        // Derive a strong encryption key using Scrypt
        byte[] derivedKey = service.buildScryptKey(metadata);
        // Store the derived key in metadata as a Hex-encoded string
        metadata.setKey(Hex.toHexString(derivedKey));
        // Encrypt the plaintext using ChaCha20 and prefix it with "PBE:" to mark it as PBE-encrypted
        return Const.PBE.getConst() + ":" + new ChaCha20AlgorithmHandler().encrypt(plainText, metadata, data);
    }

    /**
     * Decrypts the given ciphertext using **ChaCha20 Password-Based Encryption (PBE)**.
     * <p>
     * The decryption process is delegated to {@link PBAESAlgorithmHandler}.
     * </p>
     *
     * @param cipherText The ciphertext to be decrypted.
     * @param metadata The encryption metadata containing algorithm parameters.
     * @return The decrypted plaintext as a {@link String}.
     */
    @Override
    public String decrypt(String cipherText, EncryptionMetadata metadata) {
        // Delegate the decryption process to PBAESAlgorithmHandler
        return new PBAESAlgorithmHandler().decrypt(cipherText, metadata);
    }
}
