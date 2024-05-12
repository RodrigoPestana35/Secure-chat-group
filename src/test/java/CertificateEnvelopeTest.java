import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class CertificateEnvelopeTest {
    private CertificateEnvelope certificateEnvelope;
    private Encryption encription = new Encryption();

    @BeforeEach
    void setup() throws NoSuchAlgorithmException {
        byte[] test = "test".getBytes();
        KeyPair key = encription. generateKeyPair();
        this.certificateEnvelope = new CertificateEnvelope("Certificado", test , test);
    }

    @Test
    void testGetCertificate(){
        assertEquals(certificateEnvelope.getCertificate(), "Certificado");
    }

    @Test
    void testGetSignature(){
        byte[] test = "test".getBytes();
        assertNotEquals(certificateEnvelope.getSignature(), test);
    }

    @Test
    void testGetKey(){
        byte[] test = "test".getBytes();
        assertNotEquals(certificateEnvelope.getPublicKey(), test);
    }
}
