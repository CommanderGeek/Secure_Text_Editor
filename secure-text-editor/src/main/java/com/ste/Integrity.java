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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import services.EncryptionMetaDataConverter;
import services.EncryptionService;
import services.KeyStoreService;

import javax.crypto.SecretKey;
import java.security.Security;
@Path("/api")
public class Integrity {
    private static final Logger logger = LoggerFactory.getLogger(Integrity.class);
    private static final EncryptionMetaDataConverter converter = new EncryptionMetaDataConverter();
    private static final EncryptionService service = new EncryptionService();

    @POST
    @Path("/protect")
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.APPLICATION_JSON)
    public String encryptText(EncryptionRequest request) {
        Security.addProvider(new BouncyCastleProvider());
        logger.info("Received Text, ready to encrypt!");
        String plainText = request.getText();
        String mac = request.getMac().split("_")[0];
        String signature = request.getSignatureType();
        byte[] plainText2Bytes = plainText.getBytes();
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
        String computed = IntegrityHandlerFactory.
                getHandler(!data.getMac().isEmpty() ? data.getMac() : data.getSignature())
                .compute(plainText2Bytes, metadata);
        metadata.setHashValue(computed);
        String id = service.serializeMetadata(metadata);
        return "PT"+":"+id+"."+plainText;
    }

    @Path("/verify")
    @POST
    public String verify(String encryptedTextWithId) {
        Security.addProvider(new BouncyCastleProvider());
        KeyStoreService ks = new KeyStoreService();
        logger.info("Received the encrypted text");

        String[] parts = encryptedTextWithId.split("\\.");// Split on the first dot
        String fileID = parts[0];
        String text;
        if(parts.length > 1) {
            text = parts[1];
        }else{
            text = "";
        }
        EncryptionMetadata metadata = converter.lookUpMetaData(fileID);

        // Verify message integrity if a hash is provided
        if (isMessageCompromised(text, metadata)) {
            return "MESSAGE COMPROMISED!";
        } else {
            return  text;
        }
    }

    private boolean isMessageCompromised(String text, EncryptionMetadata metadata) {
        byte[] decodedText = text.getBytes();
        String hashAlgorithm = metadata.getIntegrityAlgorithm();
        if (hashAlgorithm == null || hashAlgorithm.isEmpty()) {
            return false; // No integrity check required if hash is absent
        }
        return !IntegrityHandlerFactory.getHandler(hashAlgorithm).verify(decodedText, metadata);
    }

}
