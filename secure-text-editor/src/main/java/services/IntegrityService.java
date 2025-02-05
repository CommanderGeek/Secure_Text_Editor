package services;

import DTOs.EncryptionMetadata;
import com.ste.Encryption;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class IntegrityService {
    private static final Logger logger = LoggerFactory.getLogger(IntegrityService.class);
    public byte[] sign(EncryptionMetadata metadata, byte[] plaintext, KeyPair kp){

        try {
            Signature signature = Signature.getInstance("SHA256withDSA", "BC");
            logger.info("Beginning to initSign");
            signature.initSign(kp.getPrivate());
            signature.update(plaintext);
            metadata.setPublicKey(Hex.toHexString(kp.getPublic().getEncoded()));
            metadata.setPrivateKey(Hex.toHexString(kp.getPrivate().getEncoded()));
            metadata.setIntegrityAlgorithm("SHA256withDSA");
            logger.info("Beginning to sign");
            return signature.sign();
        }
        catch (SignatureException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean verify(EncryptionMetadata metadata, byte[] signedData) {
        try {
            PublicKey key = KeyFactory.getInstance("DSA")
                    .generatePublic(new X509EncodedKeySpec(Hex.decode(metadata.getPublicKey())));

            Signature signature = Signature.getInstance("SHA256withDSA", "BC");
            signature.initVerify(key);

            signature.update(signedData);
            return signature.verify(Hex.decode(metadata.getHashValue()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
