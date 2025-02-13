package Handler;

import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import Enums.Const;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class PBAESAlgorithmHandler implements CryptoAlgorithmHandler{
    @Override
    public String encrypt(byte[] plainText, EncryptionMetadata metadata, IntegrityData data) {
        byte[] derivedKey = service.buildScryptKey(metadata);
        metadata.setKey(Hex.toHexString(derivedKey));
        return Const.PBE.getConst()+ ":"+new AESAlgorithmHandler().encrypt(plainText, metadata, data);
    }

    @Override
    public String decrypt(String cipherText, EncryptionMetadata metadata) {
        byte[] derivedKey = service.buildScryptKey(metadata);
        SecretKey key = service.buildKey(derivedKey, metadata.getAlgorithm());
        metadata.setKey(Hex.toHexString(derivedKey));
        metadata.setAlgorithm(metadata.getAlgorithm().split("_")[0]);
        Cipher c = service.buildCipher(metadata.getAlgorithm(), metadata.getMode(), metadata.getPadding());
        return service.decrypt(cipherText, c, metadata, key);
    }
}
