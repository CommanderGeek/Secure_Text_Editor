package Handler;

import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import org.bouncycastle.util.encoders.Hex;

public class PBAESAlgorithmHandler implements CryptoAlgorithmHandler{
    @Override
    public String encrypt(byte[] plainText, EncryptionMetadata metadata, IntegrityData data) {
        byte[] derivedKey = service.buildScryptKey(metadata);
        metadata.setKey(Hex.toHexString(derivedKey));
        return new AESAlgorithmHandler().encrypt(plainText, metadata, data);
    }

    @Override
    public String decrypt(String cipherText, EncryptionMetadata metadata) {
        return new AESAlgorithmHandler().decrypt(cipherText, metadata);
    }


}
