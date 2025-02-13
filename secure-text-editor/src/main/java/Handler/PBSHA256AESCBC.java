package Handler;

import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import Enums.Const;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class PBSHA256AESCBC implements CryptoAlgorithmHandler {
    @Override
    public String encrypt(byte[] plainText, EncryptionMetadata metadata, IntegrityData data) {
        byte[] derivedKey = service.buildPBEKey(metadata).getEncoded();
        metadata.setKey(Hex.toHexString(derivedKey));
        metadata.setMode(Const.CBC.getConst());
        return Const.PBE.getConst()+ ":" + new AESAlgorithmHandler().encrypt(plainText, metadata, data);
    }

    @Override
    public String decrypt(String cipherText, EncryptionMetadata metadata) {
        SecretKey key = service.buildPBEKey(metadata);
        metadata.setAlgorithm(metadata.getAlgorithm().split("_")[0]);
        Cipher c = service.buildCipher(metadata.getAlgorithm(), metadata.getMode(), metadata.getPadding());
        return service.decrypt(cipherText, c, metadata, key);
    }
}
