import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;

public class CA {
    private PrivateKey privateKey;

    public CA() throws Exception {
        KeyPair keyPair =  KeyPairGenerator.getInstance("RSA").generateKeyPair();
        this.privateKey = keyPair.getPrivate();
    }


}
