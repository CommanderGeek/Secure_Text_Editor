package Handler;

import Builder.KeyBuilder;
import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import services.EncryptionService;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Objects;

public class AESAlgorithmHandler implements CryptoAlgorithmHandler{

    private static final Logger logger = LoggerFactory.getLogger(AESAlgorithmHandler.class);

    @Override
    public String encrypt(byte[] plainText, EncryptionMetadata metadata, IntegrityData data) {

        final String AES = "AES";
        Cipher c = service.buildCipher(AES, metadata.getMode(), metadata.getPadding());
        return service.encryptAndStore(AES, c, plainText, metadata, data);
    }

    @Override
    public String decrypt(String cipherText, EncryptionMetadata metadata) {
        Cipher c = service.buildCipher(metadata.getAlgorithm(), metadata.getMode(), metadata.getPadding());
        return service.decrypt(cipherText, c, metadata);
    }
}
