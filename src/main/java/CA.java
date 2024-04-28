import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;

public class CA {
    private PrivateKey privateKey;

    public CA() throws Exception {
        KeyPair keyPair =  KeyPairGenerator.getInstance("RSA").generateKeyPair();
        this.privateKey = keyPair.getPrivate();
    }

    public void signCertificate(Certificate certificate) throws Exception {
        //logica para ir buscar o certificado

        //logica para assinar o certificado
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(this.privateKey);
        privateSignature.update(certificate.getUsername().getBytes());
        byte[] signature = privateSignature.sign();
        certificate.setSignature(signature);

    }
}
