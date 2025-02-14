package Builder;

import Enums.Const;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class KeyBuilder {

     String algorithm;
     String provider;
     int keySize;
    byte[] key;


    public KeyBuilder setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public KeyBuilder setProvider(String provider) {
        this.provider = provider;
        return this;
    }

    public KeyBuilder setKeySize(int keySize) {
        this.keySize = keySize;
        return this;
    }
    public KeyBuilder setKey(byte[] key) {
        this.key = key;
        return this;
    }

    public SecretKey build() {
        try {
            if(key != null && algorithm != null) {
                return  new SecretKeySpec(key,algorithm);
            }else if (algorithm != null && keySize > 0) {
                KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm, Const.BC.getConst());
                keyGenerator.init(keySize);
            return keyGenerator.generateKey();
            }
        }catch (NoSuchAlgorithmException e){
            System.out.println("The given Algorithm does not exists. Check the String input with setAlgorithm! ");
            System.out.println("-------------------------------");
            e.printStackTrace();
        }catch (NoSuchProviderException e){
            System.out.println("Bouncy Castle is not available? Check if the dependency is set in pom.xml!");
            System.out.println("-------------------------------");
            System.out.println("Provider not ");
            e.printStackTrace();
        }
        return null;
    }



}
