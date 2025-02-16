package Handler;

import Builder.KeyPairBuilder;
import DTOs.EncryptionMetadata;
import Enums.Const;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import services.EncryptionService;
import services.IntegrityService;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;


/**
 * @author Elias Harb
 * @version 1.0
 * The {@code SHA256DSAHandler} class provides an implementation for **digital signature generation**
 * and **verification** using the **SHA-256 with DSA (Digital Signature Algorithm)**.
 * <p>
 * This class is used to ensure the integrity and authenticity of data by signing messages and verifying their integrity.
 * It utilizes **DSA key pairs** to generate digital signatures and then validate them against original messages.
 * </p>
 *
 * <p><b>Features:</b></p>
 * <ul>
 *   <li>Generates **new DSA key pairs** for each signature computation.</li>
 *   <li>Uses **SHA-256 hashing** before signing the data.</li>
 *   <li>Signs data using **DSA (Digital Signature Algorithm)**.</li>
 *   <li>Verifies digital signatures to detect **tampering or corruption**.</li>
 * </ul>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     SHA256DSAHandler handler = new SHA256DSAHandler();
 *     String signature = handler.compute(plainText, metadata);
 *     boolean isValid = handler.verify(plainText, metadata);
 * </pre>
 *
 */

public class SHA256DSAHandler implements IntegrityHandler {

    /**
     * Computes a **SHA-256 with DSA digital signature** for the given plaintext.
     * <p>
     * The process includes:
     * <ul>
     *   <li>Generating a **new DSA key pair**.</li>
     *   <li>Signing the plaintext using **SHA-256 with DSA**.</li>
     *   <li>Returning the signature as a **Hex-encoded string**.</li>
     * </ul>
     *
     * @param plainText The plaintext data to be signed.
     * @param metadata The encryption metadata containing algorithm parameters.
     * @return A **Hex-encoded** digital signature.
     */
    private static final Logger logger = LoggerFactory.getLogger(SHA256DSAHandler.class);
    IntegrityService service = new IntegrityService();
    @Override
    public String compute(byte[] plainText, EncryptionMetadata metadata) {
        logger.info("creating keypair");
        KeyPair keyPair = new KeyPairBuilder().setAlgorithm(Const.DSA.getConst()).build();
        return Hex.toHexString(service.sign(metadata, plainText, keyPair));
    }

    /**
     * Verifies the **SHA-256 with DSA digital signature**.
     * <p>
     * The verification process includes:
     * <ul>
     *   <li>Extracting the stored signature from metadata.</li>
     *   <li>Recomputing the SHA-256 with DSA signature.</li>
     *   <li>Comparing the stored and computed signatures.</li>
     *   <li>Returning **true** if the signature is valid, otherwise **false**.</li>
     * </ul>
     *
     * @param plainText The plaintext data to verify against the signature.
     * @param metadata The encryption metadata containing the stored signature.
     * @return **True** if the signature is valid, **false** otherwise.
     */
    @Override
    public boolean verify(byte[] plainText, EncryptionMetadata metadata) {
        return service.verify(metadata, plainText);
    }
}
