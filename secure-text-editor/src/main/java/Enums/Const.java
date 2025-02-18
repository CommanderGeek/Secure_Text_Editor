package Enums;


/**
 *
 * @author Elias Harb
 * @version 1.0
 * The {@code Const} enum defines commonly used cryptographic constants
 * for encryption, hashing, and integrity mechanisms.
 * <p>
 * These constants include:
 * <ul>
 *   <li>Cryptographic providers (e.g., Bouncy Castle - BC)</li>
 *   <li>Encryption algorithms (e.g., AES, ChaCha7539, PBE)</li>
 *   <li>Hashing and MAC algorithms (e.g., HMAC-SHA256, SCRYPT)</li>
 *   <li>Key storage formats (e.g., JCEKS)</li>
 *   <li>Padding and block modes (e.g., CBC, NONE)</li>
 * </ul>
 * </p>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *    SecretKeyFactory.getInstance(Const.SCRYPT.getConst(), Const.BC.getConst());
 * </pre>
 */

public enum Const {

    BC("BC"),
    ChaCha("ChaCha7539"),
    HmacSHA256("HmacSHA256"),
    CBC("CBC"),
    DSA("DSA"),
    AES("AES"),
    PBE("PBE"),
    SCRYPT("SCRYPT"),
    SHA256withDSA("SHA256withDSA"),
    JCEKS("JCEKS"),
    PBEWithSHA256And128BitAES("PBEWithSHA256And128BitAES-CBC-BC"),
    NONE("NONE"),
    DEFAULT("DEFAULT");



    //constant variable which stores the string
    private String constant;

    /**
     * Constructor for the enum constant.
     *
     * @param constant The string representation of the constant.
     */

    Const(String constant) {
        this.constant = constant;
    }

    /**
     * Retrieves the string value of the constant.
     *
     * @return The constant as a {@link String}.
     */
    public String getConst(){
        return constant;
    }
}
