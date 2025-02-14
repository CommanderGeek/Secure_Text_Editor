package Builder;

import Enums.Const;

import java.security.*;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class KeyPairBuilder {
    private String algorithm;
    private int keySize = 3072;

    public KeyPairBuilder setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public KeyPairBuilder setKeySize(int keySize) {
        this.keySize = keySize;
        return this;
    }

    public KeyPair build()  {
        KeyPairGenerator keyPair = null;
        try {
            keyPair = KeyPairGenerator.getInstance(algorithm, Const.BC.getConst());
            keyPair.initialize(keySize);
            return keyPair.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public KeyPair buildNoSize()  {
        KeyPairGenerator keyPair = null;
        try {
            keyPair = KeyPairGenerator.getInstance(algorithm, Const.BC.getConst());
            return keyPair.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }
}
