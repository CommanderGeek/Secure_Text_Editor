package services;

import DTOs.EncryptionMetadata;
import org.bouncycastle.util.encoders.Hex;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class IntegrityService {

    public byte[] sign(EncryptionMetadata metadata, byte[] plaintext, KeyPair kp){
        try {
            Signature signature = Signature.getInstance("SHA256withDSA", "BC");
            signature.initSign(kp.getPrivate());
            signature.update(plaintext);
            metadata.setPublicKey(Hex.toHexString(kp.getPublic().getEncoded()));
            metadata.setPrivateKey(Hex.toHexString(kp.getPrivate().getEncoded()));
            metadata.setIntegrityAlgorithm("SHA256withDSA");
            return signature.sign();
        }


        catch (SignatureException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean verify(EncryptionMetadata metadata, byte[] plaintext){
        try {
            PublicKey key = KeyFactory.getInstance("DSA").generatePublic(new X509EncodedKeySpec(Hex.decode(metadata.getPublicKey())));
            Signature signature = Signature.getInstance("SHA256withDSA", "BC");
            signature.initVerify(key);
            signature.update(Hex.decode(metadata.getHashValue()));
            return  signature.verify(plaintext);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException |
                 SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}
