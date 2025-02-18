package tasks;

import Enums.Const;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class Exercise2 {
    public static void main(String[] args) {
     try {
         task();
     }
     catch(Exception e){
         e.printStackTrace();
     }
    }

    public static void task2() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        //8 Bytes
        byte[] keyBytes = Hex.decode("FFFFFFFFFFFFFFFF");

         SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
         Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding", "BC");
         byte[] input = Hex.decode("a0a1a2a3a4a5a6a7");
         System.out.println("input : " + Hex.toHexString(input));
         cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] output = cipher.doFinal(input);
        System.out.println("encrypted: " + Hex.toHexString(output));

         cipher.init(Cipher.DECRYPT_MODE, key);

         System.out.println("decrypted: " + Hex.toHexString(cipher.doFinal(output)));
    }
    public static void task() throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        String encodedText = "SoL2FA9Q9lGjhJUZjlE0qO1l2DKeeushaERgeJ/FjbYkDMh14vO9JI1NlWlp9tX2";
        String encodedKey = "5PAN+6j7FxfySdmjRlO8pA\\u003d\\u003d";

        byte[] text = Base64.getDecoder().decode(encodedText);
        byte[] keyByte = Base64.getDecoder().decode(encodedKey);

        SecretKeySpec key = new SecretKeySpec(keyByte, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");

        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(text);

        System.out.println("decrypted: " + new String(decryptedBytes));
    }

    public void robinTest() throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        KeyGenerator kg = KeyGenerator.getInstance("AES", "BC");
        kg.init(256);
        SecretKey key = kg.generateKey();
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] input = Hex.decode("a0a1a2a3a4a5a6a7");
        byte[] output = c.doFinal(input);

        c.init(Cipher.DECRYPT_MODE, key);
        c.doFinal(output);
    }

    public void robinTestChaCha() throws Exception {
        Cipher c = Cipher.getInstance("ChaCha7539", "BC");
        KeyGenerator kg = KeyGenerator.getInstance("ChaCha7539", "BC");
        kg.init(256);
        SecretKey key = kg.generateKey();
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] input = Hex.decode("a0a1a2a3a4a5a6a7");
        byte[] output = c.doFinal(input);

        c.init(Cipher.DECRYPT_MODE, key);
        c.doFinal(output);
    }

    public void robinTestDSA() throws Exception {

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DSA", "BC");
        kpGen.initialize(256);

        KeyPair kp = kpGen.generateKeyPair();

        byte[] input = Hex.decode("Hello World!");

        Signature signature = Signature.getInstance("SHA256WithDSA", "BC");

        signature.initSign(kp.getPrivate());

        signature.update(input);

        byte[] signedIn = signature.sign();

        signature.update(input);

        signature.initVerify(kp.getPublic());

        signature.verify(signedIn);
    }

    public byte[] robinMessageDigestsCompute(byte[] plainText) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256", Const.BC.getConst());
        return digest.digest(plainText);
    }

    public void robinMessageDigestsVerify() throws NoSuchAlgorithmException, NoSuchProviderException {
        byte[] plainText = "Hello World!".getBytes();
        byte[] hash = robinMessageDigestsCompute(plainText);
        byte[] falseHash = robinMessageDigestsCompute("Hallo Welt!".getBytes());

        MessageDigest.isEqual(hash, falseHash);

    }

    public byte[] robinMacCompute(byte[] plainText) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        KeyGenerator kgen = KeyGenerator.getInstance("AES", "BC");
        kgen.init(256);
        SecretKey key = kgen.generateKey();
        Mac mac = Mac.getInstance(Const.HmacSHA256.getConst(), Const.BC.getConst());
        mac.init(key);
        return mac.doFinal(plainText);
    }


    public void robinMacVerify(byte[] plainText) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        byte[] computedHash = robinMacCompute("Hello World!".getBytes());
        byte[] storedHash =  robinMacCompute("Holger ist der Beste!".getBytes());
        computedHash.equals(storedHash);
    }

    public byte[] signature() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("DSA", "BC");
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DSA", "BC");
        kpGen.initialize(256);
        KeyPair kp = kpGen.generateKeyPair();
        signature.initSign(kp.getPrivate());
        return signature.sign();
    }

    public void verify() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withDSA");
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DSA", "BC");
        kpGen.initialize(256);
        KeyPair kp = kpGen.generateKeyPair();

        signature.initVerify(kp.getPublic());
        signature.update("Test".getBytes());
        signature.verify(signature());
    }


}
