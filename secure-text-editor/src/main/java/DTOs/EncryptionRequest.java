package DTOs;

/**
 * @author Elias Harb
 * @version 1.0
 * The {@code EncryptionRequest} class is a Data Transfer Object (DTO)
 * used for handling encryption requests.
 * <p>
 * This DTO contains:
 * <ul>
 *   <li>The plaintext message that needs to be encrypted</li>
 *   <li>The encryption type (e.g., AES, ChaCha20, PBE)</li>
 *   <li>Encryption parameters such as key size, padding, and block mode</li>
 *   <li>Optional cryptographic key, MAC, password, and digital signature settings</li>
 * </ul>
 * </p>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     EncryptionRequest request = new EncryptionRequest();
 *     request.setText("Hello, World!");
 *     request.setEncryptionType("AES");
 *     request.setKeySize("256");
 *     request.setPadding("PKCS7Padding");
 *     request.setBlockMode("CBC");
 *     request.setMac("HMACSHA256");
 *     request.setPassword("securePassword123");
 * </pre>
 *
 */

public class EncryptionRequest {
    private String text;//plaintext
    private String encryptionType;//type of encryption like AES, ChaCha etc.
    private String keySize;
    private String padding;
    private String blockMode;
    private String key;//pre-generated key

    private String mac;
    private String password; //for pbe

    private String signatureType;
// Getters and Setters

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public String getEncryptionType() {
        return encryptionType;
    }


    public String getKeySize() {
        return keySize;
    }

    public void setKeySize(String keySize) {
        this.keySize = keySize;
    }


    public String getPadding() {
        return padding;
    }

    public void setPadding(String padding) {
        this.padding = padding;
    }

    public String getBlockMode() {
        return blockMode;
    }

    public void setBlockMode(String blockMode) {
        this.blockMode = blockMode;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public void setEncryptionType(String encryptionType) {
        this.encryptionType = encryptionType;
    }

    public String getMac() {
        return mac;
    }

    public void setMac(String mac) {
        this.mac = mac;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSignatureType() {
        return signatureType;
    }

    public void setSignatureType(String signatureType) {
        this.signatureType = signatureType;
    }

}
