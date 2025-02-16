package Handler;

import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import Enums.Const;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * @author Elias Harb
 * @version 1.0
 * The {@code PBAESAlgorithmHandler} class implements **Password-Based Encryption (PBE)**
 * using the **AES (Advanced Encryption Standard)** algorithm.
 * <p>
 * This handler derives a cryptographic key from a password using the **Scrypt key derivation function**.
 * It supports both encryption and decryption of data.
 * </p>
 *
 * <p><b>Features:</b></p>
 * <ul>
 *   <li>Uses Scrypt key derivation to create a strong encryption key.</li>
 *   <li>Supports AES encryption with **various block modes and paddings**.</li>
 *   <li>Prefixes the ciphertext with a PBE marker to distinguish PBE-encrypted files.</li>
 * </ul>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     PBAESAlgorithmHandler handler = new PBAESAlgorithmHandler();
 *     String encryptedData = handler.encrypt(plainText, metadata, integrityData);
 *     String decryptedData = handler.decrypt(encryptedData, metadata);
 * </pre>
 *
 */
public class PBAESAlgorithmHandler implements CryptoAlgorithmHandler{

    /**
     * Encrypts the given plaintext using **AES Password-Based Encryption (PBE)**.
     * <p>
     * The encryption process includes:
     * <ul>
     *   <li>Deriving a cryptographic key from a password using **Scrypt**.</li>
     *   <li>Storing the derived key in metadata (Hex-encoded).</li>
     *   <li>Encrypting the plaintext using **AES**.</li>
     *   <li>Prefixing the ciphertext with a PBE marker to distinguish PBE-encrypted files.</li>
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
        // Encrypt the plaintext using AES and prefix it with "PBE:" to mark it as PBE-encrypted
        return Const.PBE.getConst()+ ":"+new AESAlgorithmHandler().encrypt(plainText, metadata, data);
    }

    @Override
    public String decrypt(String cipherText, EncryptionMetadata metadata) {
        byte[] derivedKey = service.buildScryptKey(metadata);
        SecretKey key = service.buildKey(derivedKey, metadata.getAlgorithm());
        metadata.setKey(Hex.toHexString(derivedKey));
        metadata.setAlgorithm(metadata.getAlgorithm().split("_")[0]);
        Cipher c = service.buildCipher(metadata.getAlgorithm(), metadata.getMode(), metadata.getPadding());
        return service.decrypt(cipherText, c, metadata, key);
    }
}
