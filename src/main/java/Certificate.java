import java.security.PublicKey;

public class Certificate {
    private String username;
    private PublicKey publicRSAKey;
    private static int ID = 1;
    private String certificateID;

    public Certificate(String username, PublicKey publicRSAKey) {
        this.username = username;
        this.publicRSAKey = publicRSAKey;
        this.certificateID = "CERTIFICATE" + ID;
        ID++;
    }
}
