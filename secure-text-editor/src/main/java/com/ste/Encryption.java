package com.ste;
import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
import Enums.Const;
import Factory.AlgorithmHandlerFactory;
import Factory.IntegrityHandlerFactory;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import DTOs.EncryptionRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import services.EncryptionService;

import javax.crypto.SecretKey;
import java.security.Security;


/**
 * @author Elias Harb
 * @version 1.0
 * The {@code Encryption} class provides RESTful APIs for encrypting plaintext
 * and generating encryption keys.
 * <p>
 * This class supports:
 * <ul>
 *   <li>Encryption of plaintext using various encryption algorithms</li>
 *   <li>Support for multiple padding schemes, block modes, and hashing mechanisms</li>
 *   <li>Generation of encryption keys based on specified parameters</li>
 * </ul>
 * </p>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     POST /api/encrypt
 *     Body: {
 *         "text": "Hello, World!",
 *         "encryptionType": "AES",
 *         "keySize": "256",
 *         "padding": "PKCS7Padding",
 *         "blockMode": "CBC",
 *         "password": "mypassword",
 *         "signatureType": "SHA256withDSA"
 *     }
 * </pre>
 *
 */

@Path("/api")
public class Encryption {
   private static final Logger logger = LoggerFactory.getLogger(Encryption.class);

   EncryptionService service = new EncryptionService();

    /**
     * Encrypts a given plaintext using the specified encryption parameters.
     * <p>
     * This method:
     * <ul>
     *   <li>Retrieves encryption parameters from the request</li>
     *   <li>Configures metadata including padding, block mode, and hashing</li>
     *   <li>Encrypts the text using the appropriate algorithm</li>
     * </ul>
     * </p>
     *
     * @param request The {@link EncryptionRequest} containing encryption parameters and plaintext.
     * @return The encrypted text in hexadecimal format.
     */

 @POST
 @Path("/encrypt")
 @Produces(MediaType.TEXT_PLAIN)
 @Consumes(MediaType.APPLICATION_JSON)
    public String encryptText(EncryptionRequest request) {
     Security.addProvider(new BouncyCastleProvider());
       logger.info("Received Text, ready to encrypt!");
        String plainText = request.getText();
        String encryptionType = request.getEncryptionType();
        //getting the information for metadata with substrings and splits
        String keySize = request.getKeySize().substring(0,3);
        String padding = request.getPadding().split("_")[0];
        String blockMode = request.getBlockMode().split("_")[0];
        String mac = request.getMac().split("_")[0];
        String password = request.getPassword();
        String signature = request.getSignatureType();
        byte[] plainText2Bytes = plainText.getBytes();
        EncryptionMetadata metadata = new EncryptionMetadata.Builder()//
                .setKeySize(keySize)//
                .setPadding(padding)//
                .setMode(blockMode)//
                .setHash(mac)
                .setAlgorithm(request.getEncryptionType())
                .build();
        if (!request.getKey().isEmpty()){
            metadata.setKey(request.getKey());
        }

     IntegrityData data = new IntegrityData(mac, signature, encryptionType);
        if(!password.isEmpty()){
            metadata.setPassword(password);
        }
        return AlgorithmHandlerFactory.getHandler(request.getEncryptionType()).encrypt(plainText2Bytes,metadata, data);
    }

    /**
     * Generates an encryption key based on the specified algorithm and key size.
     * <p>
     * This method:
     * <ul>
     *   <li>Extracts encryption type and key size from the request</li>
     *   <li>Uses the encryption service to generate a cryptographic key</li>
     *   <li>Returns the generated key in hexadecimal format</li>
     * </ul>
     * </p>
     *
     * @param request The {@link EncryptionRequest} containing encryption type and key size.
     * @return The generated encryption key as a hexadecimal string.
     */

    @POST
    @Path("/generate-key")
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.APPLICATION_JSON)
    public String generateKey(EncryptionRequest request) {
        String encryptionType = request.getEncryptionType().split("_")[0];
        int keySize = Integer.parseInt(request.getKeySize().substring(0, 3));
        return Hex.toHexString(service.buildKey(encryptionType, Const.BC.getConst(), keySize).getEncoded());
    }
}
