package com.ste;

import DTOs.DecryptPBERequest;
import Factory.AlgorithmHandlerFactory;
import Factory.IntegrityHandlerFactory;
import Handler.SHA256Handler;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import DTOs.EncryptionMetadata;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import services.EncryptionMetaDataConverter;
import services.EncryptionService;
import services.KeyStoreService;

import javax.crypto.SecretKey;
import java.security.Security;


/**
 * @author Elias Harb
 * @version 1.0
 * The {@code Decryption} class provides RESTful APIs for decrypting encrypted text
 * and password-based encrypted (PBE) text.
 * <p>
 * This class supports:
 * <ul>
 *   <li>Standard decryption using encryption metadata</li>
 *   <li>Password-Based Encryption (PBE) decryption</li>
 *   <li>Integrity verification for ensuring data has not been tampered with</li>
 * </ul>
 * <p>
 * The decryption process involves retrieving metadata, verifying message integrity, and
 * using the appropriate cryptographic handler to perform the decryption.
 * </p>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     POST /api/decrypt
 *     Body: "c10b1c62-f7ea-4c9b-b57d-258f5a9cf381.encryptedText"
 *
 *     POST /api/decrypt/pbe
 *     Body: { "text": "c11a1c62-f7ea-4c9b-b57d-258f5a9cf381.encryptedText", "password": "myPassword123!" }
 * </pre>
 *
 */

@Path("/api/decrypt")
public class Decryption {

    private static final Logger logger =  LoggerFactory.getLogger(Decryption.class);
    private static final EncryptionMetaDataConverter converter = new EncryptionMetaDataConverter();
    private static final EncryptionService service = new EncryptionService();

    /**
     * Decrypts an encrypted text using metadata and cryptographic handlers.
     * <p>
     * This method:
     * <ul>
     *   <li>Retrieves encryption metadata based on the file ID</li>
     *   <li>Verifies message integrity if a hash is provided</li>
     *   <li>Decrypts the text using the appropriate algorithm</li>
     * </ul>
     * </p>
     *
     * @param encryptedTextWithId The encrypted text in the format "fileId.cipherText".
     * @return The decrypted text, or an error message if integrity verification fails.
     */
    @POST
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.TEXT_PLAIN)
    public Response decryptText(String encryptedTextWithId) {
        Security.addProvider(new BouncyCastleProvider());
        KeyStoreService ks = new KeyStoreService();
        logger.info("Received encrypted text for decryption");

        String[] parts = encryptedTextWithId.split("\\.");// Split on the first dot
        String fileID = parts[0];
        String cipherText;
        if(parts.length > 1) {
            cipherText = parts[1];
        }else{
            cipherText = "";
        }

        // Retrieve metadata
        EncryptionMetadata metadata = converter.lookUpMetaData(fileID);

        if (metadata == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("No metadata found for the given file ID")
                    .build();
        }

        metadata.setKey(ks.retrieveKey(metadata));

        if (metadata.getKey().isEmpty()) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("No key found for the given file ID")
                    .build();
        }

        // Verify message integrity if a hash is provided
        if (isMessageCompromised(encryptedTextWithId, metadata)) {
            logger.warn("Message verification failed: Message has been compromised.");
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("MESSAGE COMPROMISED!")
                    .build();
        }

        // Perform decryption
        String decryptedText = decryptText(cipherText, metadata);
        return Response.ok(decryptedText).build();
    }

    /**
     * API for decrypting Password-Based Encrypted (PBE) text.
     * <p>
     * This method:
     * <ul>
     *   <li>Extracts file ID and ciphertext</li>
     *   <li>Retrieves metadata and validates password</li>
     *   <li>Derives a key using PBE or Scrypt</li>
     *   <li>Verifies message integrity</li>
     *   <li>Decrypts the text</li>
     * </ul>
     * </p>
     *
     * @param request The {@link DecryptPBERequest} containing encrypted text and password.
     * @return The decrypted text, an error message if integrity is compromised, or "WRONG PASSWORD!".
     */
    @POST
    @Path("/pbe")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response decryptPBE(DecryptPBERequest request) {
        logger.info("Received PBE decryption request");

        if (request.getPassword() == null || request.getText() == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Missing password or text")
                    .build();
        }
        String[] parts = request.getText().split("\\.");// Split on the first dot
        String fileID = parts[0];
        String cipherText;
        if(parts.length > 1) {
            cipherText = parts[1];
        }else{
            cipherText = "";
        }

        EncryptionMetadata metadata = converter.lookUpMetaData(fileID);
        if (metadata == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("No metadata found for the given file ID")
                    .build();
        }

        metadata.setPassword(request.getPassword());
        // Derive key based on the encryption algorithm
        if ("PBE_PAS".equals(metadata.getAlgorithm())) {
            SecretKey derivedKey = service.buildPBEKey(metadata);
            metadata.setKey(Hex.toHexString(derivedKey.getEncoded()));
        } else {
            metadata.setKey(Hex.toHexString(service.buildScryptKey(metadata)));
        }
        // Check for integrity compromise
        if (isMessageCompromised(request.getText(), metadata)) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("MESSAGE COMPROMISED!")
                    .build();
        }
        // Verify password
        if (!new SHA256Handler().verify(metadata.getPassword().getBytes(), Hex.decode(metadata.getPasswordHash()))) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("WRONG PASSWORD!")
                    .build();
        }
        // Perform decryption
        String decryptedText = AlgorithmHandlerFactory.getHandler(metadata.getAlgorithm()).decrypt(cipherText, metadata);
        return Response.ok(decryptedText).build();
    }


    /**
     * Performs decryption using the specified metadata.
     * <p>
     * The method extracts the base algorithm (if prefixed with an underscore) and
     * calls the appropriate algorithm handler for decryption.
     * </p>
     *
     * @param encryptedText The encrypted text to be decrypted.
     * @param metadata The metadata containing algorithm, mode, and key details.
     * @return The decrypted plaintext.
     * @throws IllegalArgumentException If the algorithm is null or empty.
     */

    String decryptText(String encryptedText, EncryptionMetadata metadata) {
        if (metadata.getAlgorithm() == null || metadata.getAlgorithm().isEmpty()) {
            throw new IllegalArgumentException("Algorithm cannot be null or empty");
        }
        String baseAlgorithm = metadata.getAlgorithm().contains("_")
                ? metadata.getAlgorithm().split("_")[0]
                : metadata.getAlgorithm();
        metadata.setAlgorithm(baseAlgorithm);
        return AlgorithmHandlerFactory.getHandler(metadata.getAlgorithm()).decrypt(encryptedText, metadata);
    }



    /**
     * Checks whether the message integrity is compromised by verifying its hash/MAC.
     * <p>
     * If the integrity algorithm is specified, this method verifies whether the computed
     * hash matches the expected hash value stored in metadata.
     * </p>
     *
     * @param text The encrypted text in hexadecimal format.
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
