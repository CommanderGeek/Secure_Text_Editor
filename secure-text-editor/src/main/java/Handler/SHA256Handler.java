package Handler;

import DTOs.EncryptionMetadata;
import Enums.Const;
import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author Elias Harb
 * @version 1.0
 *
 * The {@code SHA256Handler} class provides an implementation for computing and verifying **SHA-256 hash values**.
 * <p>
 * It is primarily used to:
 * <ul>
 *   <li>Generate SHA-256 hashes for **message integrity verification**.</li>
 *   <li>Compare stored hash values to check for **data integrity**.</li>
 *   <li>Verify passwords against their **stored hash values**.</li>
 * </ul>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     SHA256Handler handler = new SHA256Handler();
 *     String hash = handler.compute(plainText, metadata);
 *     boolean isValid = handler.verify(plainText, metadata);
 * </pre>
 *
 */
public class SHA256Handler implements IntegrityHandler {

    /**
     * Computes a **SHA-256 hash** for the given plaintext.
     * <p>
     * The process includes:
     * <ul>
     *   <li>Retrieving the integrity algorithm from **metadata**.</li>
     *   <li>Using **SHA-256** as the hashing algorithm.</li>
     *   <li>Returning the **Hex-encoded** SHA-256 hash.</li>
     * </ul>
     *
     * @param plainText The plaintext data to be hashed.
     * @param metadata The encryption metadata containing the integrity algorithm.
     * @return The **Hex-encoded SHA-256 hash**.
     */
    @Override
    public String compute(byte[] plainText, EncryptionMetadata metadata) {
        try {
            MessageDigest digest = MessageDigest.getInstance(metadata.getIntegrityAlgorithm(), Const.BC.getConst());
            return Hex.toHexString(digest.digest(plainText));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }
    /**
     * Verifies if the computed SHA-256 hash matches the stored hash value.
     * <p>
     * The verification process includes:
     * <ul>
     *   <li>Computing the **SHA-256 hash** of the provided plaintext.</li>
     *   <li>Retrieving the **stored hash value** from metadata.</li>
     *   <li>Performing a **secure comparison** to check if they match.</li>
     * </ul>
     *
     * @param plainText The plaintext data to verify.
     * @param metadata The encryption metadata containing the stored hash value.
     * @return **True** if the computed hash matches the stored hash, otherwise **false**.
     */

    @Override
    public boolean verify(byte[] plainText, EncryptionMetadata metadata) {
        byte[] computedHash = Hex.decode(compute(plainText, metadata));
        byte[] storedHash = Hex.decode(metadata.getHashValue());
        return MessageDigest.isEqual(computedHash, storedHash);
    }


    /**
     * Verifies if the computed SHA-256 hash of the password matches the stored hash.
     * <p>
     * The verification process includes:
     * <ul>
     *   <li>Hashing the provided password using **SHA-256**.</li>
     *   <li>Retrieving the **stored password hash**.</li>
     *   <li>Performing a **secure comparison**.</li>
     * </ul>
     *
     * @param password The password input as a byte array.
     * @param storedHash The stored hashed password for comparison.
     * @return **True** if the computed hash matches the stored hash, otherwise **false**.
     */

    public boolean verify(byte[] password, byte[] storedHash) {
        byte[] computedHash = Hex.decode(compute(password,
                new EncryptionMetadata(new EncryptionMetadata.Builder().setIntegrityAlgorithm("SHA-256"))));
        return MessageDigest.isEqual(computedHash, storedHash);
    }

}
