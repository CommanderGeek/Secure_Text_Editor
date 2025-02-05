package Handler;

import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import services.EncryptionService;

public interface CryptoAlgorithmHandler {
    EncryptionService service = new EncryptionService();
    String encrypt(byte[] plainText, EncryptionMetadata metadata, IntegrityData data);
    String decrypt(String cipherText, EncryptionMetadata metadata);
}

