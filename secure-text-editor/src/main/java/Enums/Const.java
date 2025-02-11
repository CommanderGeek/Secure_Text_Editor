package Enums;

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
    DEFAULT("DEFAULT");




    private String constant;

    Const(String constant) {
        this.constant = constant;
    }

    public String getConst(){
        return constant;
    }
}
