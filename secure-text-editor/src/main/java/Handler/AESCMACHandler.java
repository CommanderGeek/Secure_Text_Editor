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

public class AESCMACHandler implements IntegrityHandler {
    private static final Logger logger = LoggerFactory.getLogger(AESCMACHandler.class);
    private final EncryptionService service = new EncryptionService();
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

    @Override
    public boolean verify(byte[] plainText, EncryptionMetadata metadata) {
            byte[] computedHash = Hex.decode(compute(plainText,metadata)); // Compute the hash of the input text
            byte[] storedHash = Hex.decode(metadata.getHashValue()); // Decode the stored hash from metadata
            return MessageDigest.isEqual(computedHash, storedHash); // Secure comparison of hashes

    }
}
