import java.io.Serializable;

/**
 * This class represents a certificate envelope object that is sent between the client and the server.
 */
public class CertificateEnvelope implements Serializable {
    private final String certificate;
    private byte[] signature;
    private byte[] publicKey;

    /**
     * Constructs a CertificateEnvelope object by specifying the certificate string that will be sent between the client and the server.
     *
     * @param certificate the certificate that is sent to the server
     */
    public CertificateEnvelope(String certificate, byte[] signature, byte[] publicKey) {
        this.certificate = certificate;
        this.signature = signature;
        this.publicKey = publicKey;
    }

    /**
     * Gets the certificate string.
     *
     * @return the certificate string
     */
    public CertificateEnvelope(String certificate) {
        this.certificate = certificate;
    }

    /**
     * Gets the certificate string.
     *
     * @return the certificate string
     */
    public String getCertificate() {
        return certificate;
    }

    /**
     * Gets the signature bytes.
     *
     * @return the signature bytes
     */
    public byte[] getSignature() {
        return signature;
    }

    /**
     * Gets the public key bytes.
     *
     * @return the public key bytes
     */
    public byte[] getPublicKey() {
        return publicKey;
    }
}
