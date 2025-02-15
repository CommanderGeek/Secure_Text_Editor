package Factory;

import Handler.*;

public class AlgorithmHandlerFactory {
    public static CryptoAlgorithmHandler getHandler(String algorithm) {
        return switch (algorithm) {
            case "AES_SYM", "AES" -> new AESAlgorithmHandler();
            case "ChaCha7539", "ChaCha20_SYM", "ChaCha20" -> new ChaCha20AlgorithmHandler();
            case "AES_AEM" -> new AEMAlgorithmHandler();
            case "AES_PAS" -> new PBAESAlgorithmHandler();
            case "ChaCha20_PAS" -> new PBChaCha20AlgorithmHandler();
            case "PBEWithSHA256And128BitAES-CBC-BC", "PBE_PAS" -> new PBSHA256AESCBC();
            default -> throw new UnsupportedOperationException("Algorithm not supported");
        };
    }
}