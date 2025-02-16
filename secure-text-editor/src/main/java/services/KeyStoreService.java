package services;

import Builder.KeyBuilder;
import DTOs.EncryptionMetadata;
import Enums.Const;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Iterator;

/**
 * @author Elias Harb
 * @version 1.0
 * The `KeyStoreService` class manages encryption keys in a secure **Java Keystore (JCEKS)** format.
 * It provides functionality to store and retrieve cryptographic keys used in encryption/decryption.
 *
 * <h2>How it Works:</h2>
 * <ul>
 *     <li>**storeKey:** Saves a generated secret key into a keystore file.</li>
 *     <li>**retrieveKey:** Loads the stored key from the keystore for decryption.</li>
 * </ul>
 *
 * <h2>Keystore Details:</h2>
 * <ul>
 *     <li>Uses **JCEKS** (Java Cryptography Extension KeyStore) for better security.</li>
 *     <li>Keys are stored in **P12 files** under `~/STE/encryption/keys/`.</li>
 *     <li>Each key is protected with a **randomly generated password**.</li>
 * </ul>
 *
 * <p><b>Note:</b> This class requires the **Bouncy Castle** security provider.</p>
 *
 */

public class KeyStoreService {

    /**
     * The base directory where encryption keys are stored.
     */
    final Path baseDir = Paths.get(System.getProperty("user.home"), "STE", "encryption", "keys");

    /**
     * Stores an encryption key securely in a JCEKS keystore file.
     *
     * <p>The key is saved under a unique **file ID** generated in `EncryptionMetadata`.
     * A **random 32-byte password** is used to protect the key entry in the keystore.</p>
     *
     * @param metadata The encryption metadata containing the file ID and algorithm details.
     * @param key      The secret key to be stored (in byte array format).
     * @throws RuntimeException If an error occurs during key storage.
     */

    public void storeKey(EncryptionMetadata metadata, byte[] key) {
        Security.addProvider(
                new BouncyCastleProvider());
        try {

            EncryptionMetaDataConverter converter = new EncryptionMetaDataConverter();
            converter.createDirectories(baseDir);
            KeyStore keyStore = KeyStore.getInstance(Const.JCEKS.getConst());
            keyStore.load(null, null);
            SecretKey secretKey = new KeyBuilder().setKey(key).setAlgorithm(metadata.getAlgorithm()).build();

            SecureRandom random = SecureRandom.getInstance(Const.DEFAULT.getConst(), Const.BC.getConst());
            byte[] password = new byte[32];
            random.nextBytes(password);

            KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(Arrays.toString(password).toCharArray());
            KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
            keyStore.setEntry(metadata.getFileId(), secretKeyEntry, protectionParam);
            Path filePath = baseDir.resolve(metadata.getFileId() + ".p12");

            try (FileOutputStream fos = new FileOutputStream(filePath.toString())) {
                keyStore.store(fos, Arrays.toString(password).toCharArray());
                metadata.setKeyStorePassword(Hex.toHexString(password));
            }

        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }

    }


    /**
     * Retrieves a stored secret key from the keystore.
     *
     * <p>The method looks up the file ID in `EncryptionMetadata`, loads the corresponding
     * keystore file, and retrieves the **encrypted secret key**.</p>
     *
     * @param metadata The encryption metadata containing the file ID and password.
     * @return The stored key in **hex-encoded format**.
     * @throws RuntimeException If the key cannot be found or decrypted.
     */

    public String retrieveKey(EncryptionMetadata metadata) {
        try {
            FileInputStream fis = new FileInputStream(baseDir.resolve(metadata.getFileId() + ".p12").toFile());
            KeyStore keyStore = KeyStore.getInstance(Const.JCEKS.getConst());
            char[] password = Arrays.toString(Hex.decode(metadata.getKeyStorePassword())).toCharArray();
            keyStore.load(fis, password);

            // Retrieve public key from certificate
            String alias = metadata.getFileId();
            SecretKey secretKey = (SecretKey) keyStore.getKey(alias, password);

            return Hex.toHexString(secretKey.getEncoded());
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }

}
