package DTOs;



/**
 * @author Elias Harb
 * @version 1.0
 * The {@code DecryptPBERequest} class is a Data Transfer Object (DTO)
 * used for handling password-based encryption (PBE) decryption requests.
 * <p>
 * This DTO contains:
 * <ul>
 *   <li>The encrypted text that needs to be decrypted</li>
 *   <li>The password used for decryption</li>
 * </ul>
 * </p>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     DecryptPBERequest request = new DecryptPBERequest();
 *     request.setText("encryptedText");
 *     request.setPassword("securePassword123");
 * </pre>
 *
 */
public class DecryptPBERequest {
    private String text;
    private String password;

    // Getters and Setters
    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
