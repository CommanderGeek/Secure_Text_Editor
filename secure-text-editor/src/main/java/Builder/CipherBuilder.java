package Builder;

import Enums.Const;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class CipherBuilder {

    private String algo;
    private String mode;
    private String padding;

    public CipherBuilder setAlgorithm(String algo) {
        this.algo = algo;
        return this;
    }

    public CipherBuilder setMode(String mode){
        this.mode = mode;
        return this;
    }

    public CipherBuilder setPadding(String padding){
        this.padding = padding;
        return this;
    }

    public Cipher build() {
        try {
            if (algo != null && mode != null && padding != null) {
                Security.addProvider(new BouncyCastleProvider());
                String input = algo + "/" + mode + "/" + padding;
                return Cipher.getInstance(input, Const.BC.getConst());
            }
        }catch (NoSuchPaddingException e){
            System.out.println("The given Padding does not exists. Check the String input with setPadding! ");
            System.out.println("-------------------------------");
            e.printStackTrace();
        }catch (NoSuchAlgorithmException e){
            System.out.println("The given Algorithm does not exists. Check the String input with setAlgorithm! ");
            System.out.println("-------------------------------");
            e.printStackTrace();
        }catch (NoSuchProviderException e){
            System.out.println("Bouncy Castle is not available? Check if the dependency is set in pom.xml!");
            System.out.println("-------------------------------");
            e.printStackTrace();
        }
        return null;
    }

    public Cipher build(String algo){
        try {
            if (algo != null) {
                Security.addProvider(new BouncyCastleProvider());
                String provider = "BC";
                return Cipher.getInstance(algo, provider);
            }
        }catch (NoSuchPaddingException e){
            System.out.println("The given Padding does not exists. Check the String input with setPadding! ");
            System.out.println("-------------------------------");
            e.printStackTrace();
        }catch (NoSuchAlgorithmException e){
            System.out.println("The given Algorithm does not exists. Check the String input with setAlgorithm! ");
            System.out.println("-------------------------------");
            e.printStackTrace();
        }catch (NoSuchProviderException e){
            System.out.println("Bouncy Castle is not available? Check if the dependency is set in pom.xml!");
            System.out.println("-------------------------------");
            e.printStackTrace();
        }
        return null;
    }

}
