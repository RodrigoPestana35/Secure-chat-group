import java.io.Serializable;

public class CertificateEnvelope implements Serializable {
    private String certificate;
    private byte[] signature;
    private byte[] publicKey;

    public CertificateEnvelope(String certificate, byte[] signature, byte[] publicKey) {
        this.certificate = certificate;
        this.signature = signature;
        this.publicKey = publicKey;
    }

    public CertificateEnvelope(String certificate) {
        this.certificate = certificate;
    }

    public String getCertificate() {
        return certificate;
    }

    public byte[] getSignature() {
        return signature;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }
}
