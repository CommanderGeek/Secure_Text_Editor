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
 * The {@code PBSHA256AESCBC} class provides an implementation for **Password-Based Encryption (PBE)**
 * using the **AES-CBC (Cipher Block Chaining) mode with SHA-256 for key derivation**.
 * <p>
 * This handler uses **PBKDF2 (Password-Based Key Derivation Function 2) or Scrypt**
 * to derive a cryptographic key from a password. It then encrypts or decrypts data using **AES in CBC mode**.
 * </p>
 *
 * <p><b>Features:</b></p>
 * <ul>
 *   <li>Uses **PBKDF2 or Scrypt** to generate a **secure key** from a password.</li>
 *   <li>Encrypts data using **AES with CBC mode**.</li>
 *   <li>Prefixes ciphertext with a **PBE marker** to indicate password-based encryption.</li>
 *   <li>Supports integrity checking with MACs or signatures.</li>
 * </ul>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     PBSHA256AESCBC handler = new PBSHA256AESCBC();
 *     String encryptedData = handler.encrypt(plainText, metadata, integrityData);
 *     String decryptedData = handler.decrypt(encryptedData, metadata);
 * </pre>
 *
 */
public class PBSHA256AESCBC implements CryptoAlgorithmHandler {

    /**
     * Encrypts the given plaintext using **AES-CBC Password-Based Encryption (PBE)**.
     * <p>
     * The encryption process includes:
     * <ul>
     *   <li>Deriving a cryptographic key from a password using **PBKDF2 or Scrypt**.</li>
     *   <li>Storing the derived key in metadata (Hex-encoded).</li>
     *   <li>Encrypting the plaintext using **AES in CBC mode** via {@link AESAlgorithmHandler}.</li>
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
        // Derive the encryption key using PBKDF2 or Scrypt
        byte[] derivedKey = service.buildPBEKey(metadata).getEncoded();
        // Store the derived key in metadata as a Hex-encoded string
        metadata.setKey(Hex.toHexString(derivedKey));
        // Ensure that AES encryption is performed using CBC mode
        metadata.setMode(Const.CBC.getConst());
        // Encrypt the plaintext using AES-CBC and prefix it with "PBE:"
        return Const.PBE.getConst() + ":" + new AESAlgorithmHandler().encrypt(plainText, metadata, data);
    }

    /**
     * Decrypts the given ciphertext using **AES-CBC Password-Based Encryption (PBE)**.
     * <p>
     * The decryption process includes:
     * <ul>
     *   <li>Extracting the derived key using PBKDF2 or Scrypt.</li>
     *   <li>Generating a **SecretKey** for AES decryption.</li>
     *   <li>Initializing a Cipher instance with **CBC mode and correct padding**.</li>
     *   <li>Decrypting the ciphertext to recover the original plaintext.</li>
     * </ul>
     *
     * @param cipherText The ciphertext to be decrypted.
     * @param metadata The encryption metadata containing algorithm parameters.
     * @return The decrypted plaintext as a {@link String}.
     */
    @Override
    public String decrypt(String cipherText, EncryptionMetadata metadata) {
        // Derive the encryption key using PBKDF2 or Scrypt
        SecretKey key = service.buildPBEKey(metadata);
        // Normalize the algorithm name by removing "_PAS" suffix if present
        metadata.setAlgorithm(metadata.getAlgorithm().split("_")[0]);
        // Initialize a Cipher instance for AES-CBC decryption
        Cipher c = service.buildCipher(metadata.getAlgorithm(), metadata.getMode(), metadata.getPadding());
        // Decrypt and return the original plaintext
        return service.decrypt(cipherText, c, metadata, key);
    }
}
