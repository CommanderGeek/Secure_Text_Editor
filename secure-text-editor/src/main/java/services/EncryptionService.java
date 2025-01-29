package services;

import Builder.CipherBuilder;
import Builder.KeyBuilder;
import DTOs.EncryptionMetadata;
import Handler.AESAlgorithmHandler;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;
/**
 * This class provides encryption services.
 * It supports encrypting and decrypting text, building ciphers, and handling encryption metadata.
 *  @author Elias Harb
 */

public class EncryptionService {


    private static final EncryptionMetaDataConverter converter = new EncryptionMetaDataConverter();
    private static final Logger logger = LoggerFactory.getLogger(EncryptionService.class);
    /**
     * serializes the MetaData into Json files and triggers the storing function
     * @param algorithm
     * @param key
     * @param iv
     * @return the UUID of the encrypted file
     */
    public String prepareAndSerializeMetadata(String algorithm, EncryptionMetadata metadata,
                                              byte[] key, byte[] iv) {
        Security.addProvider(new BouncyCastleProvider());
        logger.debug("here are the parameters: \n mode: " +metadata.getMode() +" \n padding: "+ metadata.getPadding()+" \n key: " + key.toString());
        metadata = new EncryptionMetadata.Builder().setAlgorithm(algorithm)//
                .setMode(metadata.getMode())//
                .setPadding(metadata.getPadding())//
                .setKeySize(metadata.getKeySize())//
                .setIv(Hex.toHexString(Objects.requireNonNullElseGet(iv, "null"::getBytes)))//
                .setFileId(java.util.UUID.randomUUID().toString())//
                .build();
        KeyStoreService ks = new KeyStoreService();
        ks.storeKey(metadata, key);
        converter.storeMetaData(converter.serializeMetadata(metadata), UUID.fromString(metadata.getFileId()));



        return metadata.getFileId();
    }

    public String serializeMetadata(EncryptionMetadata encryptionMetadata){
        converter.storeMetaData(converter.serializeMetadata(encryptionMetadata), UUID.fromString(encryptionMetadata.getFileId()));
        return encryptionMetadata.getFileId();
    }

    private byte[] encrypt(Cipher c, byte[] byteText, SecretKey key){
        try{
            c.init(Cipher.ENCRYPT_MODE, key);
            logger.info("finished encryption!");
            return c.doFinal(byteText);
        }catch (InvalidKeyException e){
            System.out.println("Invalid key is inserted, someone did an upsi here!");
            System.out.println("-------------------------------");
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            System.out.println("This blocksize is not suitable. Look up!");
            System.out.println("-------------------------------");
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            System.out.println("Bad padding! take a look at the inserted padding");
            System.out.println("-------------------------------");
            e.printStackTrace();
            throw new RuntimeException(e);
        }
        return null;
    }

    public String encryptAndStore(String algorithm, Cipher c, byte[] plainText, EncryptionMetadata metadata){
        SecretKey key;
        if(metadata.getKey() == null){
            key = buildKey(algorithm,"BC",Integer.parseInt(metadata.getKeySize()));
        }else{
            key = buildKey(Hex.decode(metadata.getKey()), algorithm);
        }
        byte[] encryptedText =  encrypt(c, plainText, key);
        String fileId = prepareAndSerializeMetadata(algorithm, metadata, key.getEncoded(),c.getIV());
        String encEncryptedText = Hex.toHexString(encryptedText);
        logger.info("finished encryption!");
        return fileId+"."+encEncryptedText;
    }


    public byte[] encryptAEM(Cipher c, byte[] byteText, SecretKey key, EncryptionMetadata metadata){
        try{
            AlgorithmParameterGenerator pGen = AlgorithmParameterGenerator.getInstance(metadata.getMode(),"BC");
            AlgorithmParameters pGCM = pGen.generateParameters();
            GCMParameterSpec gcmSpec = pGCM.getParameterSpec(GCMParameterSpec.class);
            metadata.setTagLen(String.valueOf(gcmSpec.getTLen()));
            c.init(Cipher.ENCRYPT_MODE, key, pGCM);
            return c.doFinal(byteText);
        }catch (InvalidKeyException e){
            System.out.println("Invalid key is inserted, someone did an upsi here!");
            System.out.println("-------------------------------");
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            System.out.println("This blocksize is not suitable. Look up!");
            System.out.println("-------------------------------");
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            System.out.println("Bad padding! take a look at the inserted padding");
            System.out.println("-------------------------------");
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            System.out.println("Invalid Algorithm Parameter! take a look at the inserted parameters");
            System.out.println("-------------------------------");
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidParameterSpecException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    public byte[] decrypt(Cipher c, byte[] encryptedByteText,SecretKey key){
        try {
            c.init(Cipher.DECRYPT_MODE,key);
            return c.doFinal(encryptedByteText);
        }catch (InvalidKeyException e){
            System.out.println("Invalid key is inserted, someone did an upsi here!");
            System.out.println("-------------------------------");
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            System.out.println("This blocksize is not suitable. Look up!");
            System.out.println("-------------------------------");
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            System.out.println("Bad padding! take a look at the inserted padding");
            System.out.println("-------------------------------");
            e.printStackTrace();
            throw new RuntimeException(e);
        }
        return null;
    }

    public byte[] decrypt(Cipher c, byte[] encryptedByteText, SecretKey key, IvParameterSpec iv){
        try {
            c.init(Cipher.DECRYPT_MODE,key, iv);
            logger.info("finished decryption!");
            return c.doFinal(encryptedByteText);
        }catch (InvalidKeyException e){
            System.out.println("Invalid key is inserted, someone did an upsi here!");
            System.out.println("-------------------------------");
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            System.out.println("This blocksize is not suitable. Look up!");
            System.out.println("-------------------------------");
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            System.out.println("Bad padding! take a look at the inserted padding");
            System.out.println("-------------------------------");
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    public String decrypt(String cipherText, Cipher c,EncryptionMetadata metadata){
        byte[] text = Hex.decode(cipherText);
        byte[] keyByte = Hex.decode(metadata.getKey());
        SecretKey key = buildKey(keyByte, metadata.getAlgorithm());
        byte[] iv = Hex.decode(metadata.getIv());
        byte[] decryptedByteText;
        if (Arrays.equals(iv, Hex.decode("6e756c6c"))){
            decryptedByteText = decrypt(c,text,key);
        }else {
            decryptedByteText = decrypt(c, text, key, new IvParameterSpec(iv));
        }
        String decryptedText = new String(decryptedByteText);
        logger.info("Successfully decrypted the text with result: "+decryptedText);
        return decryptedText;
    }

    public byte[] decryptAEM(Cipher c, byte[] encryptedByteText, SecretKey key, byte[] iv, int tagLen){
        try {
            GCMParameterSpec spec = new GCMParameterSpec(tagLen, iv);
            c.init(Cipher.DECRYPT_MODE,key, spec);
            return c.doFinal(encryptedByteText);
        }catch (InvalidKeyException e){
            System.out.println("Invalid key is inserted, someone did an upsi here!");
            System.out.println("-------------------------------");
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            System.out.println("This blocksize is not suitable. Look up!");
            System.out.println("-------------------------------");
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            System.out.println("Bad padding! take a look at the inserted padding");
            System.out.println("-------------------------------");
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    public Cipher buildCipher(String algorithm, String mode, String padding){
        if(algorithm.equals("PBE")){
            return new CipherBuilder().setAlgorithm("AES")//
                    .setMode(mode)//
                    .setPadding(padding)//
                    .build();
        }
        return new CipherBuilder().setAlgorithm(algorithm)//
                .setMode(mode)//
                .setPadding(padding)//
                .build();
    }

    public Cipher buildCipher(String algorithm){
        return new CipherBuilder().build(algorithm);
    }

    public SecretKey buildKey(String algorithm, String provider, int keySize){
        Security.addProvider(new BouncyCastleProvider());
        return new KeyBuilder().
                setAlgorithm(algorithm)//
                .setKeySize(keySize)//
                .setProvider(provider)//
                .build();
    }

    public SecretKey buildKey(byte[] keyByte, String algorithm){
        return new KeyBuilder().setKey(keyByte).setAlgorithm(algorithm).build();
    }

    public byte[] buildScryptKey(EncryptionMetadata metadata){
        try {
        byte[] salt = generateSalt(Integer.parseInt(metadata.getKeySize())/8);
        metadata.setSalt(Hex.toHexString(salt));
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("SCRYPT", "BC");
        ScryptKeySpec scryptKeySpec = new ScryptKeySpec(
                metadata.getPassword().toCharArray(),
                salt,
                16384, // CPU/Memory cost parameter (N)
                8,     // Block size (r)
                1,     // Parallelization parameter (p)
                Integer.parseInt(metadata.getKeySize())    // Key size in bytes (256 bits)
        );

            return keyFactory.generateSecret(scryptKeySpec).getEncoded();
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public SecretKey buildPBEKey(EncryptionMetadata metadata)  {
        try {
        KeySpec spec = new PBEKeySpec(metadata.getPassword().toCharArray(),
                generateSalt(Integer.parseInt(metadata.getKeySize())/8), 20000,
                Integer.parseInt(metadata.getKeySize()));
        SecretKeyFactory factory =
                SecretKeyFactory.getInstance("PBEWithSHA256And128BitAES-CBC-BC", "BC");
        return factory.generateSecret(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] generateSalt(int length) {
        byte[] salt = new byte[length];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        return salt;
    }
}
