package Handler;

import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import Enums.Const;
import org.bouncycastle.util.encoders.Hex;

public class PBChaCha20AlgorithmHandler implements CryptoAlgorithmHandler {
    @Override
    public String encrypt(byte[] plainText, EncryptionMetadata metadata, IntegrityData data) {
        byte[] derivedKey = service.buildScryptKey(metadata);
        metadata.setKey(Hex.toHexString(derivedKey));
        return Const.PBE.getConst()+ ":" + new ChaCha20AlgorithmHandler().encrypt(plainText, metadata, data);
    }

    @Override
    public String decrypt(String cipherText, EncryptionMetadata metadata) {
        return new PBAESAlgorithmHandler().decrypt(cipherText, metadata);
    }
}
