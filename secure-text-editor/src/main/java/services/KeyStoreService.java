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

public class KeyStoreService {
    final Path baseDir = Paths.get(System.getProperty("user.home"), "STE", "encryption", "keys");

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

    public String retrieveKey(EncryptionMetadata metadata) {
        try {
            FileInputStream fis = new FileInputStream(baseDir.resolve(metadata.getFileId() + ".p12").toFile());
            KeyStore keyStore = KeyStore.getInstance(Const.JCEKS.getConst());
            char[] password = Arrays.toString(Hex.decode(metadata.getKeyStorePassword())).toCharArray();
            keyStore.load(fis, password);

            // Retrieve public key from certificate
            String alias = metadata.getFileId();
            SecretKey secretKey = (SecretKey) keyStore.getKey(alias, password);

             Iterator<String> it = keyStore.aliases().asIterator();
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
