package services;

import Builder.CipherBuilder;
import Builder.KeyBuilder;
import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import Enums.Const;
import Factory.IntegrityHandlerFactory;
import Handler.AESAlgorithmHandler;
import Handler.SHA256Handler;
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
 * @author Elias Harb
 *
 * EncryptionService provides functionality for encrypting and decrypting data using various cryptographic algorithms.
 * It supports AES, PBE, Scrypt, and ChaCha20 encryption methods, along with key generation and metadata handling.
 *
 */
public class EncryptionService {


    private static final EncryptionMetaDataConverter converter = new EncryptionMetaDataConverter();
    private static final Logger logger = LoggerFactory.getLogger(EncryptionService.class);
    /**
     * Serializes the encryption metadata and stores the encryption key if needed.
     *
     * @param md   The encryption metadata.
     * @param key  The encryption key in byte format.
     * @return The unique file ID associated with the encrypted data.
     */
    private String prepareAndSerializeMetadata(EncryptionMetadata md,
                                              byte[] key) {
        Security.addProvider(new BouncyCastleProvider());
        logger.debug("here are the parameters: \n mode: " +md.getMode() +" \n padding: "+ md.getPadding()+" \n key: " + key.toString());
        EncryptionMetadata metadata = new EncryptionMetadata.Builder().setAlgorithm(md.getAlgorithm())//
                .setMode(md.getMode())//
                .setPadding(md.getPadding())//
                .setKeySize(md.getKeySize())//
                .setIv(md.getIv())//
                .setHashValue(md.getHashValue())
                .setMacKey(md.getMacKey())
                .setIntegrityAlgorithm(md.getIntegrityAlgorithm())
                .setFileId(java.util.UUID.randomUUID().toString())//
                .setPublicKey(md.getPublicKey())//
                .setSalt(md.getSalt())
                .build();
        if (md.getPassword() == null || md.getPassword().isEmpty()) {
            KeyStoreService ks = new KeyStoreService();
            ks.storeKey(metadata, key);
        }else{
            md.setIntegrityAlgorithm("SHA-256");
            metadata.setPasswordHash(new SHA256Handler().compute(md.getPassword().getBytes(), md));
        }
        return serializeMetadata(metadata);
    }

    /**
     * Serializes and stores encryption metadata.
     *
     * @param encryptionMetadata The metadata to serialize.
     * @return The unique file ID for the stored metadata.
     */
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
        return new byte[0];
    }

    /**
     * Encrypts the given plaintext and stores the encrypted data.
     *
     * @param algorithm The encryption algorithm.
     * @param c        The cipher instance.
     * @param plainText The plaintext in byte format.
     * @param metadata  The encryption metadata.
     * @param data      The integrity data (MAC or signature).
     * @return The encrypted text with its associated file ID.
     */
    public String encryptAndStore(String algorithm, Cipher c, byte[] plainText, EncryptionMetadata metadata,
                                  IntegrityData data){
        SecretKey key;
        if(metadata.getKey() == null){
            key = buildKey(algorithm, Const.BC.getConst(), Integer.parseInt(metadata.getKeySize()));
        }else if(metadata.getAlgorithm().equals("AES_PAS") || metadata.getAlgorithm().equals("ChaCha20_PAS")){
           key = buildKey(buildScryptKey(metadata), "AES");
        }else{
            key = buildKey(Hex.decode(metadata.getKey()), algorithm);
        }
        byte[] encryptedText =  encrypt(c, plainText, key);
        if(!data.getMac().isEmpty()) {
            SecretKey macKey  = buildKey(Const.AES.getConst(), Const.BC.getConst(), Integer.parseInt(metadata.getKeySize()));
            metadata.setMacKey(Hex.toHexString(macKey.getEncoded()));
            metadata.setIntegrityAlgorithm(data.getMac());
            metadata.setHashValue(IntegrityHandlerFactory.getHandler(data.getMac()).compute(encryptedText, metadata));
        }else if (!data.getSignature().isEmpty()){
            metadata.setIntegrityAlgorithm(data.getSignature());
            metadata.setHashValue(IntegrityHandlerFactory.getHandler(data.getSignature()).compute(encryptedText, metadata));
        }
        metadata.setIv(Hex.toHexString(Objects.requireNonNullElseGet(c.getIV(), "null"::getBytes)));
        String fileId = prepareAndSerializeMetadata(metadata, key.getEncoded());
        String encEncryptedText = Hex.toHexString(encryptedText);


        logger.info("finished encryption and stored file!");
        return fileId+"."+encEncryptedText;
    }

    /**
     * Decrypts an encrypted text using the provided cipher and key.
     *
     * @param c          The cipher instance configured for decryption.
     * @param key   The encryption metadata containing algorithm and key details.
     * @return The decrypted plaintext as a String.
     */
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
        return new byte[0];
    }

    /**
     * Decrypts an encrypted text using the provided cipher and key.
     *
     * @param c          The cipher instance configured for decryption.
     * @param encryptedByteText the encrypted byte text
     * @param key   The required secretkey for encryption
     * @param iv the used iv
     * @return The decrypted plaintext as a String.
     */

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
        return new byte[0];
    }


    /**
     * Decrypts an encrypted text using the provided cipher and key.
     *
     * @param cipherText The encrypted text in hexadecimal format.
     * @param c          The cipher instance configured for decryption.
     * @param metadata   The encryption metadata containing algorithm and key details.
     * @return The decrypted plaintext as a String.
     */
    public String decrypt(String cipherText, Cipher c,EncryptionMetadata metadata){
        byte[] text = Hex.decode(cipherText);
        byte[] keyByte = Hex.decode(metadata.getKey());
        SecretKey key;
        if(metadata.getAlgorithm().equals(Const.PBEWithSHA256And128BitAES.getConst())) {
            key = buildPBEKey(metadata);
        }else {
            key = buildKey(keyByte, metadata.getAlgorithm());
        }

        byte[] iv = Hex.decode(metadata.getIv());
        byte[] decryptedByteText;
        if (Arrays.equals(iv, Hex.decode("6e756c6c"))){
            decryptedByteText = decrypt(c,text,key);
        }else {
            decryptedByteText = decrypt(c, text, key, new IvParameterSpec(iv));
        }
        String decryptedText = new String(decryptedByteText);
        logger.info("Successfully decrypted the text with result: \n"+decryptedText);
        return decryptedText;
    }
    /**
     * Decrypts an encrypted text using the provided cipher and key.
     *
     * @param cipherText The encrypted text in hexadecimal format.
     * @param c          The cipher instance configured for decryption.
     * @param metadata   The encryption metadata containing algorithm and key details.
     * @return The decrypted plaintext as a String.
     */
    public String decrypt(String cipherText, Cipher c,EncryptionMetadata metadata, SecretKey key){
        byte[] text = Hex.decode(cipherText);
        byte[] iv = Hex.decode(metadata.getIv());
        byte[] decryptedByteText;
        if (Arrays.equals(iv, Hex.decode("6e756c6c"))){
            decryptedByteText = decrypt(c,text,key);
        }else {
            decryptedByteText = decrypt(c, text, key, new IvParameterSpec(iv));
        }
        String decryptedText = new String(decryptedByteText);
        logger.info("Successfully decrypted the text with result: \n"+decryptedText);
        return decryptedText;
    }


    /**
     * Builds a cipher instance for encryption or decryption.
     *
     * @param algorithm The algorithm name (e.g., "AES").
     * @param mode      The mode (e.g., "CBC").
     * @param padding   The padding scheme (e.g., "PKCS7Padding").
     * @return The initialized Cipher instance.
     */
    public Cipher buildCipher(String algorithm, String mode, String padding){
        if(algorithm.equals(Const.PBE.getConst())){
            return new CipherBuilder().setAlgorithm(Const.AES.getConst())//
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

    /**
     * Generates a cryptographic key.
     *
     * @param algorithm The algorithm for the key (e.g., "AES").
     * @param provider  The security provider (e.g., "BC").
     * @param keySize   The size of the key in bits.
     * @return The generated SecretKey.
     */
    public SecretKey buildKey(String algorithm, String provider, int keySize){
        Security.addProvider(new BouncyCastleProvider());
        return new KeyBuilder().
                setAlgorithm(algorithm)//
                .setKeySize(keySize)//
                .setProvider(provider)//
                .build();
    }

    /**
     * Generates a cryptographic key.
     *
     * @param algorithm The algorithm for the key (e.g., "AES").
     * @param keyByte  byte array of an existing key
     * @return The generated SecretKey.
     */
    public SecretKey buildKey(byte[] keyByte, String algorithm){
        return new KeyBuilder().setKey(keyByte).setAlgorithm(algorithm).build();
    }

    /**
     * Generates a Scrypt-based key from metadata.
     *
     * @param metadata The encryption metadata.
     * @return The generated key as a byte array.
     */
    public byte[] buildScryptKey(EncryptionMetadata metadata){
        try {
        byte[] salt = metadata.getSalt() == null ? generateSalt(Integer.parseInt(metadata.getKeySize())/8, metadata) : Hex.decode(metadata.getSalt());
        int n = 65536;
        int r = 8;
        int p = 1;
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(Const.SCRYPT.getConst(), Const.BC.getConst());
        ScryptKeySpec scryptKeySpec = new ScryptKeySpec(
                metadata.getPassword().toCharArray(),
                salt,
                n, // CPU/Memory cost parameter (N)
                r,     // Block size (r)
                p,     // Parallelization parameter (p)
                Integer.parseInt(metadata.getKeySize())    // Key size in bytes (256 bits)
        );

            return keyFactory.generateSecret(scryptKeySpec).getEncoded();
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generates a PBE (Password-Based Encryption) key using metadata.
     *
     * @param metadata The encryption metadata.
     * @return The generated SecretKey.
     */
    public SecretKey buildPBEKey(EncryptionMetadata metadata)  {
        try {
            int iterations = 20000;
            byte[] salt = metadata.getSalt() == null ? generateSalt(Integer.parseInt(metadata.getKeySize())/8, metadata) : Hex.decode(metadata.getSalt());
        KeySpec spec = new PBEKeySpec(metadata.getPassword().toCharArray(),
                salt, iterations,
                Integer.parseInt(metadata.getKeySize()));
        SecretKeyFactory factory =
                SecretKeyFactory.getInstance(Const.PBEWithSHA256And128BitAES.getConst(), Const.BC.getConst());
        return factory.generateSecret(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generates a cryptographic salt.
     *
     * @param length   The length of the salt.
     * @param metadata The encryption metadata.
     * @return The generated salt as a byte array.
     */
    private byte[] generateSalt(int length, EncryptionMetadata metadata) {
        byte[] salt = new byte[length];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        metadata.setSalt(Hex.toHexString(salt));
        return salt;
    }
}
