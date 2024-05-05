import java.io.Serializable;
import java.security.PublicKey;

public class Certificate implements Serializable {
    private String username;
    private PublicKey publicRSAKey;
    private static int ID = 1;
    private String certificateID;
    private byte[] signature;

    public Certificate(String username, PublicKey publicRSAKey) {
        this.username = username;
        this.publicRSAKey = publicRSAKey;
        this.certificateID = "CERTIFICATE" + ID;
        ID++;
    }


    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public String getUsername() {
        return username;
    }

}
