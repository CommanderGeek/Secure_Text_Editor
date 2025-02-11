package Builder;

import Enums.Const;

import java.security.*;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class KeyPairBuilder {
    String algorithm;

    public KeyPairBuilder setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public KeyPair build()  {
        KeyPairGenerator keyPair = null;
        try {
            keyPair = KeyPairGenerator.getInstance(algorithm, Const.BC.getConst());
            keyPair.initialize(3072);
            return keyPair.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }
}
