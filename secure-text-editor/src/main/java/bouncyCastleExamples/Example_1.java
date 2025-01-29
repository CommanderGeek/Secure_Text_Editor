package bouncyCastleExamples;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Base64;

public class Example_1{

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
        //important always load bouncycastle provider before starting to use it
        Security.addProvider(
                new BouncyCastleProvider());
        SecureRandom random = SecureRandom.getInstance("DEFAULT", "BC");

        AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DSA", "BC");
        gen.init(2048);
        AlgorithmParameters params = gen.generateParameters();
        DSAParameterSpec dsaParameterSpec = params.getParameterSpec(DSAParameterSpec.class);

        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("DSA", "BC");
        keyPair.initialize(dsaParameterSpec, new SecureRandom());
        KeyPair kp = keyPair.generateKeyPair();

        Signature sign = Signature.getInstance("SHA256withDSA", "BC");
        sign.initSign(kp.getPrivate());
        sign.update("Hello World!".getBytes());
        byte[] signed = sign.sign();

        System.out.println("Signed String is: " + Arrays.toString(signed));

        sign = Signature.getInstance("SHA256withDSA", "BC");
        sign.initVerify(kp.getPublic());
        sign.update("Hello World!".getBytes());
        boolean right = sign.verify(signed);
        System.out.println("Signature is verified: " + right);
        KeyPair kp2 = keyPair.generateKeyPair();

        System.out.println("Here kp1 public! " +kp.getPublic());
        System.out.println("Here kp2 public! " +kp2.getPublic());

    }
}