package DTOs;

import Enums.Const;


/**
 * @author Elias Harb
 * @version 1.0
 * The {@code IntegrityData} class is a Data Transfer Object (DTO)
 * used for handling integrity protection details, such as message authentication codes (MAC)
 * and digital signatures.
 * <p>
 * This DTO contains:
 * <ul>
 *   <li>The MAC algorithm used for integrity verification</li>
 *   <li>The signature type used for authentication</li>
 *   <li>The encryption type associated with the integrity protection</li>
 * </ul>
 * </p>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     IntegrityData integrity = new IntegrityData("HMACSHA256", "SHA256withDSA", "AES");
 * </pre>
 *
 */
public class IntegrityData {
    private String mac;
    private String signature;
    private String encryptionType;


    /**
     * Constructs an {@code IntegrityData} object with a MAC, a signature, and an encryption type.
     *
     * @param mac The MAC algorithm used (e.g., HMACSHA256).
     * @param signature The digital signature algorithm used (e.g., SHA256withDSA).
     * @param encryptionType The encryption type used (e.g., AES).
     */

    public IntegrityData(String mac, String signature, String encryptionType) {
        this.mac = mac;
        this.signature = signature;
        this.encryptionType = encryptionType;
    }

    /**
     * Constructs an {@code IntegrityData} object with a MAC and a signature.
     * <p>
     * The encryption type defaults to {@link Const#NONE}.
     * </p>
     *
     * @param mac The MAC algorithm used (e.g., HMACSHA256).
     * @param signature The digital signature algorithm used (e.g., SHA256withDSA).
     */
    public IntegrityData(String mac, String signature) {
        this.mac = mac;
        this.signature = signature;
        this.encryptionType = Const.NONE.getConst();
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getMac() {
        return mac;
    }

    public void setMac(String mac) {
        this.mac = mac;
    }

    public String getEncryptionType() {
        return encryptionType;
    }

    public void setEncryptionType(String encryptionType) {
        this.encryptionType = encryptionType;
    }
}
