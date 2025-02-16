package Handler;

import DTOs.EncryptionMetadata;
import Enums.Const;
import org.bouncycastle.util.encoders.Hex;
import services.EncryptionService;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author Elias Harb
 * @version 1.0
 * The {@code HMACSHA256Handler} class implements integrity protection using the
 * **HMAC-SHA256 (Hash-based Message Authentication Code)** algorithm.
 * <p>
 * HMAC-SHA256 provides **message integrity and authentication** by generating
 * a cryptographic hash using a **secret key**.
 * </p>
 *
 * <p><b>Features:</b></p>
 * <ul>
 *   <li>Computes HMAC-SHA256 hashes to ensure message integrity</li>
 *   <li>Verifies stored HMAC values against recomputed hashes</li>
 *   <li>Uses BouncyCastle as the cryptographic provider</li>
 * </ul>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     HMACSHA256Handler handler = new HMACSHA256Handler();
 *     String hmacValue = handler.compute(plainText, metadata);
 *     boolean isValid = handler.verify(plainText, metadata);
 * </pre>
 *
 */

public class HMACSHA256Handler implements IntegrityHandler {

    private final EncryptionService service = new EncryptionService();

    /**
     * Computes an **HMAC-SHA256** hash for the given plaintext using a secret key.
     * <p>
     * The computation process includes:
     * <ul>
     *   <li>Retrieving the secret key from encryption metadata</li>
     *   <li>Initializing an HMAC instance with the secret key</li>
     *   <li>Computing the MAC (Message Authentication Code) over the plaintext</li>
     * </ul>
     *
     * @param plainText The plaintext data for which the HMAC is computed.
     * @param metadata The encryption metadata containing the MAC key.
     * @return The computed HMAC-SHA256 hash as a hexadecimal {@link String}.
     * @throws RuntimeException if the key is invalid or the algorithm is unavailable.
     */

    @Override
    public String compute(byte[] plainText, EncryptionMetadata metadata) {
        try {
            SecretKey key = service.buildKey(Hex.decode(metadata.getMacKey()), Const.HmacSHA256.getConst());
            Mac mac = Mac.getInstance(Const.HmacSHA256.getConst(), Const.BC.getConst());
            mac.init(key);
            return Hex.toHexString(mac.doFinal(plainText));
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Error computing HMAC-SHA256 hash", e);
        }
    }


    /**
     * Verifies the integrity of a given plaintext by comparing its computed HMAC
     * with the stored hash in metadata.
     * <p>
     * The verification process includes:
     * <ul>
     *   <li>Computing the HMAC-SHA256 hash of the input text</li>
     *   <li>Decoding the stored hash from metadata</li>
     *   <li>Securely comparing the computed and stored hashes</li>
     * </ul>
     *
     * @param plainText The plaintext data to verify.
     * @param metadata The encryption metadata containing the stored HMAC.
     * @return {@code true} if the computed and stored hashes match, {@code false} otherwise.
     * @throws RuntimeException if verification fails due to an error.
     */

    @Override
    public boolean verify(byte[] plainText, EncryptionMetadata metadata) {
        try {
            // Recompute the hash and compare it with the stored hash
            String computedHash = compute(plainText, metadata);
            return MessageDigest.isEqual(
                    Hex.decode(computedHash),
                    Hex.decode(metadata.getHashValue())
            );
        } catch (Exception e) {
            throw new RuntimeException("Error verifying HMAC-SHA256 hash", e);
        }
    }
}
