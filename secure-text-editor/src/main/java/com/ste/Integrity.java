package com.ste;

import DTOs.EncryptionMetadata;
import DTOs.EncryptionRequest;
import DTOs.IntegrityData;
import Enums.Const;
import Factory.IntegrityHandlerFactory;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import services.EncryptionMetaDataConverter;
import services.EncryptionService;
import javax.crypto.SecretKey;
import java.security.Security;
import java.util.UUID;

/**
 * @author Elias Harb
 * @version 1.0
 *
 * The {@code Integrity} class provides RESTful APIs for protecting and verifying
 * message integrity using cryptographic hashing and signing mechanisms.
 * <p>
 * This class supports:
 * <ul>
 *   <li>Adding integrity protection to plaintext using a MAC or digital signature</li>
 *   <li>Verifying the integrity of a protected message</li>
 * </ul>
 * </p>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     POST /api/protect
 *     Body: {
 *         "text": "Hello, World!",
 *         "mac": "HMACSHA256",
 *         "signatureType": "SHA256withDSA"
 *     }
 *
 *     POST /api/verify
 *     Body: "fileId.encryptedText"
 * </pre>
 *
 */

@Path("/api")
public class Integrity {
    //for logging the method calls and progress
    private static final Logger logger = LoggerFactory.getLogger(Integrity.class);
    //converter for getting the metadata from drive
    private static final EncryptionMetaDataConverter converter = new EncryptionMetaDataConverter();
    //for serializing the metadata
    private static final EncryptionService service = new EncryptionService();


    /**
     * Adds integrity protection to a given plaintext using a MAC or digital signature.
     * <p>
     * This method:
     * <ul>
     *   <li>Extracts the MAC or signature type from the request</li>
     *   <li>Generates a cryptographic hash or digital signature</li>
     *   <li>Returns the protected message with an integrity identifier</li>
     * </ul>
     * </p>
     *
     * @param request The {@link EncryptionRequest} containing plaintext and integrity parameters.
     * @return The integrity-protected message in the format {@code "PT:fileId.encryptedText"}.
     */
    @POST
    @Path("/protect")
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.APPLICATION_JSON)
    public String secureText(EncryptionRequest request) {
        Security.addProvider(new BouncyCastleProvider());
        logger.info("Received Text, ready to encrypt!");
        //splitting the request
        String plainText = request.getText();
        String mac = request.getMac().split("_")[0];
        String signature = request.getSignatureType();
        IntegrityData data = new IntegrityData(mac, signature);
        EncryptionMetadata metadata = new EncryptionMetadata.Builder()//
                .setHash(mac)
                .setAlgorithm(request.getEncryptionType())
                .setIntegrityAlgorithm(!data.getMac().isEmpty() ? data.getMac() : data.getSignature())
                .setFileId(java.util.UUID.randomUUID().toString())
                .build();
        if(!data.getMac().isEmpty()){
            SecretKey macKey  = service.buildKey(Const.AES.getConst(), Const.BC.getConst(), 256);
            metadata.setMacKey(Hex.toHexString(macKey.getEncoded()));
        }
        String id = UUID.randomUUID().toString();
        metadata.setFileId(id);
        String output = id+"."+plainText;
        String computed = IntegrityHandlerFactory.
                getHandler(!data.getMac().isEmpty() ? data.getMac() : data.getSignature())
                .compute(output.getBytes(), metadata);
        if(!data.getMac().isEmpty()){
            metadata.setHashValue(computed);
        }else{
            metadata.setSignature(computed);
        }
        service.serializeMetadata(metadata);
        return "PT"+":"+output;
    }

    /**
     * Verifies the integrity of a protected message.
     * <p>
     * This method:
     * <ul>
     *   <li>Extracts the file ID and protected text</li>
     *   <li>Verifies the integrity hash or signature</li>
     *   <li>Returns the original text if integrity is confirmed</li>
     * </ul>
     * </p>
     *
     * @param encryptedTextWithId The integrity-protected message in the format {@code "fileId.encryptedText"}.
     * @return The original plaintext if integrity is verified, otherwise "MESSAGE COMPROMISED!".
     */
    @Path("/verify")
    @POST
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.TEXT_PLAIN)
    public Response verify(String encryptedTextWithId) {
        Security.addProvider(new BouncyCastleProvider());
        logger.info("Received the encrypted text");

        int dotIndex = encryptedTextWithId.indexOf(".");
        String fileID;
        String text;

        if (dotIndex == -1) {
            // No dot found, handle error or default behavior
            fileID = "-1";
            text = ""; // No ciphertext available
        } else {
            fileID = encryptedTextWithId.substring(0, dotIndex); // Extract file ID
            text = encryptedTextWithId.substring(dotIndex + 1); // Extract rest as text, preserving spaces
        }
        EncryptionMetadata metadata = converter.lookUpMetaData(fileID);

        if (metadata == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("No metadata found for the given file ID")
                    .build();
        }

        // Verify message integrity if a hash is provided
        if (isMessageCompromised(encryptedTextWithId, metadata)) {
            logger.warn("Message verification failed: Message has been compromised.");
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("MESSAGE COMPROMISED!")
                    .build();
        } else {
            logger.info("Verification successful. Returning the original message.");
            return Response.ok(text).build();
        }
    }

    /**
     * Checks whether the message integrity is compromised by verifying its hash or signature.
     * <p>
     * If the integrity algorithm is specified, this method verifies whether the computed
     * hash matches the expected hash value stored in metadata.
     * </p>
     *
     * @param text The protected text.
     * @param metadata The metadata containing integrity verification details.
     * @return {@code true} if the message is compromised, otherwise {@code false}.
     */
    private boolean isMessageCompromised(String text, EncryptionMetadata metadata) {
        byte[] decodedText = text.getBytes();
        String hashAlgorithm = metadata.getIntegrityAlgorithm();
        if (hashAlgorithm == null || hashAlgorithm.isEmpty()) {
            return false; // No integrity check required if hash is absent
        }
        return !IntegrityHandlerFactory.getHandler(hashAlgorithm).verify(decodedText, metadata);
    }

}
