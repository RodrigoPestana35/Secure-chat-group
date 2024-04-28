import java.security.*;

public class CA {
    private PublicKey publicRSAKey;
    private PrivateKey privateRSAKey;

    public CA() throws Exception {
        KeyPair keyPair =  KeyPairGenerator.getInstance("RSA").generateKeyPair();
        this.publicRSAKey = keyPair.getPublic();
        this.privateRSAKey = keyPair.getPrivate();
    }

    public void signCertificate(Certificate certificate) throws Exception {
        //logica para ir buscar o certificado

        //logica para assinar o certificado
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(this.privateRSAKey);
        privateSignature.update(certificate.getUsername().getBytes());
        byte[] signature = privateSignature.sign();
        certificate.setSignature(signature);

    }
}
