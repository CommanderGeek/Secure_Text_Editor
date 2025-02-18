package services;

import DTOs.EncryptionMetadata;
import Enums.Const;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;


/**
 * @author Elias Harb
 * The `IntegrityService` class handles cryptographic signing and verification of data integrity.
 * It uses the **SHA256withDSA** algorithm for signing and verifying digital signatures.
 *
 * This service ensures that encrypted data remains unaltered and authentic.
 *
 */

public class IntegrityService {
    private static final Logger logger = LoggerFactory.getLogger(IntegrityService.class);


    /**
     * Signs the given plaintext using the provided key pair and stores metadata.
     *
     * <p> The signing process involves:
     * <ol>
     *     <li>Initializing a SHA256withDSA signature.</li>
     *     <li>Signing the provided plaintext using the private key.</li>
     *     <li>Storing the public/private key and algorithm in metadata.</li>
     * </ol>
     *
     * @param metadata  The encryption metadata where signature-related information is stored.
     * @param plaintext The byte array of the plaintext data to be signed.
     * @param kp        The key pair used for signing (DSA private key required).
     * @return The generated digital signature as a byte array.
     * @throws RuntimeException If an error occurs during the signing process.
     */

    public byte[] sign(EncryptionMetadata metadata, byte[] plaintext, KeyPair kp){

        try {
            Signature signature = Signature.getInstance(Const.SHA256withDSA.getConst(), Const.BC.getConst());
            logger.info("Beginning to initSign");
            signature.initSign(kp.getPrivate());
            signature.update(plaintext);
            metadata.setPublicKey(Hex.toHexString(kp.getPublic().getEncoded()));
            metadata.setPrivateKey(Hex.toHexString(kp.getPrivate().getEncoded()));
            metadata.setIntegrityAlgorithm(Const.SHA256withDSA.getConst());
            logger.info("Beginning to sign");
            return signature.sign();
        }
        catch (SignatureException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }


    /**
     * Verifies the integrity of signed data using the stored public key.
     *
     * <p> The verification process follows these steps:
     * <ol>
     *     <li>Retrieve the public key from stored metadata.</li>
     *     <li>Initialize a SHA256withDSA signature verifier.</li>
     *     <li>Verify the given signed data against the stored hash.</li>
     * </ol>
     *
     * @param metadata   The encryption metadata containing the stored public key and hash value.
     * @param signedData The signed data that needs to be verified.
     * @return {@code true} if the signature is valid, otherwise {@code false}.
     * @throws RuntimeException If an error occurs during the verification process.
     */

    public boolean verify(EncryptionMetadata metadata, byte[] signedData) {
        try {
            // Convert the stored public key from Hex to PublicKey object
            PublicKey key = KeyFactory.getInstance(Const.DSA.getConst())
                    .generatePublic(new X509EncodedKeySpec(Hex.decode(metadata.getPublicKey()), Const.DSA.getConst()));

            Signature signature = Signature.getInstance(Const.SHA256withDSA.getConst(), Const.BC.getConst());
            signature.initVerify(key);

            signature.update(signedData);
            // Verify the signature against the stored enc value metadata
            return signature.verify(Hex.decode(metadata.getSignature()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
