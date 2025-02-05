package Handler;

import Builder.KeyPairBuilder;
import DTOs.EncryptionMetadata;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import services.EncryptionService;
import services.IntegrityService;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class SHA256DSAHandler implements IntegrityHandler {

    private static final Logger logger = LoggerFactory.getLogger(SHA256DSAHandler.class);
    IntegrityService service = new IntegrityService();
    @Override
    public String compute(byte[] plainText, EncryptionMetadata metadata) {
        String keyPairAlgo = "DSA";
        logger.info("creating keypair");
        KeyPair keyPair = new KeyPairBuilder().setAlgorithm(keyPairAlgo).build();
        return Hex.toHexString(service.sign(metadata, plainText, keyPair));
    }

    @Override
    public boolean verify(byte[] plainText, EncryptionMetadata metadata) {
        return service.verify(metadata, plainText);
    }
}
