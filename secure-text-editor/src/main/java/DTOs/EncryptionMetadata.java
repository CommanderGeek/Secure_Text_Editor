package DTOs;

public class EncryptionMetadata {

    private String fileId;
    private String algorithm;
    private String mode;
    private String padding;
    private String keySize;
    private String key;  // Hex encoded key
    private String iv;   // Hex encoded IV
    private String integrityAlgorithm;
    private String hashValue;
    private String macKey;
    private String tagLen;

    //ToDo: Hash it!
    private String password;

    private String salt;
    private String publicKey;
    private String privateKey;

    private String keyStorePassword;

    public EncryptionMetadata(Builder builder){
        fileId = builder.fileId;
        algorithm = builder.algorithm;
        mode = builder.mode;
        padding = builder.padding;
        keySize = builder.keySize;
        key = builder.key;
        iv = builder.iv;
        integrityAlgorithm = builder.hash;
        hashValue = builder.hashValue;
        macKey = builder.macKey;
        tagLen = builder.tagLen;
        password = builder.password;
    }


    // Getters and setters for all fields
    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public String getPadding() {
        return padding;
    }

    public void setPadding(String padding) {
        this.padding = padding;
    }

    public String getKeySize() {
        return keySize;
    }

    public void setKeySize(String keySize) {
        this.keySize = keySize;
    }

    public String getKey() {
        return key;
    }

    public String getMacKey() {
        return macKey;
    }

    public void setMacKey(String macKey) {
        this.macKey = macKey;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public String getIntegrityAlgorithm() {
        return integrityAlgorithm;
    }

    public String getHashValue() {
        return hashValue;
    }
    public void setIntegrityAlgorithm(String integrityAlgorithm) {
        this.integrityAlgorithm = integrityAlgorithm;
    }

    public String getFileId() {
        return fileId;
    }

    public void setFileId(String fileId) {
        this.fileId = fileId;
    }
    public void setHashValue(String hash){this.hashValue = hash; }

    public String getTagLen() {
        return tagLen;
    }

    public void setTagLen(String tagLen) {
        this.tagLen = tagLen;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public static class Builder {
        private String fileId;
        private String algorithm;
        private String mode;
        private String padding;
        private String keySize;
        private String key;
        private String iv;
        private String hash;
        private String hashValue;
        private String encryptedText;

        private String macKey;

        private String tagLen;
        private String password;
        private String salt;

        private String publicKey;
        private String privateKey;

        private String getTagLen() {
            return tagLen;
        }

        private void setTagLen(String tagLen) {
            this.tagLen = tagLen;
        }

        private String keyStorePassword;

        public String getFileId() {
            return fileId;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public String getMode() {
            return mode;
        }

        public String getPadding() {
            return padding;
        }

        public String getKeySize() {
            return keySize;
        }

        public String getKey() {
            return key;
        }

        public String getIv() {
            return iv;
        }

        public String getHash() {
            return hash;
        }

        public String getHashValue() {
            return hashValue;
        }

        public String getEncryptedText() {
            return encryptedText;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getSalt() {
            return salt;
        }

        public void setSalt(String salt) {
            this.salt = salt;
        }

        public String getKeyStorePassword() {
            return keyStorePassword;
        }

        public void setKeyStorePassword(String keyStorePassword) {
            this.keyStorePassword = keyStorePassword;
        }

        // Builder methods for each field
        public Builder setFileId(String fileId) {
            this.fileId = fileId;
            return this;
        }

        public Builder setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Builder setMode(String mode) {
            this.mode = mode;
            return this;
        }

        public Builder setPadding(String padding) {
            this.padding = padding;
            return this;
        }

        public Builder setKeySize(String keySize) {
            this.keySize = keySize;
            return this;
        }

        public Builder setKey(String key) {
            this.key = key;
            return this;
        }

        public Builder setIv(String iv) {
            this.iv = iv;
            return this;
        }

        public Builder setHash(String hash) {
            this.hash = hash;
            return this;
        }

        public Builder setHashValue(String hashValue) {
            this.hashValue = hashValue;
            return this;
        }
        public Builder setEncryptedText(String encryptedText) {
            this.encryptedText = encryptedText;
            return this;
        }

        public String getMacKey() {
            return macKey;
        }

        public void setMacKey(String macKey) {
            this.macKey = macKey;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(String publicKey) {
            this.publicKey = publicKey;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }

        // Build method to create EncryptionMetadata object
        public EncryptionMetadata build() {
            return new EncryptionMetadata(this);
        }
    }
}
