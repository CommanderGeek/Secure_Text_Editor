package com.ste;
import DTOs.EncryptionMetadata;
import DTOs.IntegrityData;
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

@Path("/api")
public class Encryption {
   private static final Logger logger = LoggerFactory.getLogger(Encryption.class);

   EncryptionService service = new EncryptionService();

 @POST
 @Path("/encrypt")
 @Produces(MediaType.TEXT_PLAIN)
 @Consumes(MediaType.APPLICATION_JSON)
    public String encryptText(EncryptionRequest request) {
     Security.addProvider(new BouncyCastleProvider());
        //TODO: pls first concat the Hashvalue with the plaintext and then encrypt! Output length of Hashvalue is same!
        // Extract the text and encryption parameters from the request
       logger.info("Received Text, ready to encrypt!");
        String plainText = request.getText();
        String encryptionType = request.getEncryptionType().split("_")[0];
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
    @POST
    @Path("/generate-key")
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.APPLICATION_JSON)
    public String generateKey(EncryptionRequest request) {
        String encryptionType = request.getEncryptionType().split("_")[0];
        int keySize = Integer.parseInt(request.getKeySize().substring(0, 3));
        return Hex.toHexString(service.buildKey(encryptionType, "BC", keySize).getEncoded());
    }
}
