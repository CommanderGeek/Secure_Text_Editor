package Handler;

import Builder.MacBuilder;
import DTOs.EncryptionMetadata;
import Enums.Const;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import services.EncryptionService;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.MessageDigest;

/**
 * @author Elias Harb
 * @version 1.0
 * The {@code AESCMACHandler} class implements **AES-based CMAC (Cipher-based Message Authentication Code)**
 * for integrity verification in encryption processes.
 * <p>
 * CMAC ensures **message integrity and authentication** by generating a cryptographic hash based on AES.
 * This class provides functionality for:
 * <ul>
 *   <li>Computing CMAC hashes for message integrity</li>
 *   <li>Verifying integrity using a stored hash</li>
 * </ul>
 * </p>
 *
 * <p><b>Features:</b></p>
 * <ul>
 *   <li>Uses AES-CMAC for message authentication</li>
 *   <li>Computes and verifies integrity using cryptographic hashing</li>
 *   <li>Securely compares computed and stored hashes</li>
 * </ul>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     AESCMACHandler handler = new AESCMACHandler();
 *     String macValue = handler.compute(plainText, metadata);
 *     boolean isValid = handler.verify(plainText, metadata);
 * </pre>
 *
 */
public class AESCMACHandler implements IntegrityHandler {
    private static final Logger logger = LoggerFactory.getLogger(AESCMACHandler.class);
    private final EncryptionService service = new EncryptionService();

    /**
     * Computes the AES-CMAC (Cipher-based Message Authentication Code) for the given plaintext.
     * <p>
     * The computation process includes:
     * <ul>
     *   <li>Building a MAC instance using the specified algorithm</li>
     *   <li>Deriving a secret key from the metadata</li>
     *   <li>Computing the CMAC hash for the plaintext</li>
     * </ul>
     *
     * @param plainText The plaintext data for which the CMAC hash is computed.
     * @param metadata The encryption metadata containing the MAC key and algorithm.
     * @return The computed CMAC hash as a hexadecimal {@link String}.
     * @throws RuntimeException if the MAC key is invalid.
     */
    @Override
    public String compute(byte[] plainText, EncryptionMetadata metadata) {
        try {
            Mac mac = new MacBuilder(metadata.getIntegrityAlgorithm()).build();
            SecretKey key = service.buildKey(Hex.decode(metadata.getMacKey()), Const.AES.getConst());
            String k = Hex.toHexString(key.getEncoded());
           logger.info(k);
            mac.init(key);
            mac.update(plainText);
            return Hex.toHexString(mac.doFinal());
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Verifies the integrity of a given plaintext by comparing its computed CMAC hash
     * with the stored hash in metadata.
     * <p>
     * The verification process includes:
     * <ul>
     *   <li>Computing the CMAC hash of the input text</li>
     *   <li>Decoding the stored hash from metadata</li>
     *   <li>Securely comparing the computed and stored hashes</li>
     * </ul>
     *
     * @param plainText The plaintext data to verify.
     * @param metadata The encryption metadata containing the stored hash.
     * @return {@code true} if the computed and stored hashes match, {@code false} otherwise.
     */
    @Override
    public boolean verify(byte[] plainText, EncryptionMetadata metadata) {
            byte[] computedHash = Hex.decode(compute(plainText,metadata)); // Compute the hash of the input text
            byte[] storedHash = Hex.decode(metadata.getHashValue()); // Decode the stored hash from metadata
            return MessageDigest.isEqual(computedHash, storedHash); // Secure comparison of with MessageDigests

    }
}
