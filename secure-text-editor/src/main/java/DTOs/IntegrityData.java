package DTOs;

public class IntegrityData {
    private String mac;
    private String signature;
    private String encryptionType;

    public IntegrityData(String mac, String signature, String encryptionType) {
        this.mac = mac;
        this.signature = signature;
        this.encryptionType = encryptionType;
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
