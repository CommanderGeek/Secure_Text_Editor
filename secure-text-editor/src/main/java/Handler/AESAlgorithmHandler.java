package Handler;

import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import Enums.Const;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;

public class AESAlgorithmHandler implements CryptoAlgorithmHandler{

    private static final Logger logger = LoggerFactory.getLogger(AESAlgorithmHandler.class);

    @Override
    public String encrypt(byte[] plainText, EncryptionMetadata metadata, IntegrityData data) {

        Cipher c = service.buildCipher(Const.AES.getConst(), metadata.getMode(), metadata.getPadding());
        return service.encryptAndStore(Const.AES.getConst(), c, plainText, metadata, data);
    }

    @Override
    public String decrypt(String cipherText, EncryptionMetadata metadata) {
        Cipher c = service.buildCipher(metadata.getAlgorithm(), metadata.getMode(), metadata.getPadding());
        return service.decrypt(cipherText, c, metadata);
    }
}
