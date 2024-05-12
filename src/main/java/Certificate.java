import java.io.Serializable;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class Certificate implements Serializable {
    private String username;
    private PublicKey publicRSAKey;
    private static int ID = 1;
    private String certificateID;
    private byte[] signature;
    private boolean revogado = false;
    private LocalDateTime date;

    public Certificate(String username, PublicKey publicRSAKey, LocalDateTime date) {
        this.username = username;
        this.publicRSAKey = publicRSAKey;
        this.certificateID = "CERTIFICATE" + ID;
        this.date = date;
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

    public PublicKey getPublicRSAKey() {
        return publicRSAKey;
    }

    public LocalDateTime getDate(){
        return date;
    }

    public boolean isRevogado() {
        return revogado;
    }

    public void checkRevogado() {
        LocalDateTime now = LocalDateTime.now();
        Date out = Date.from(now.atZone(ZoneId.systemDefault()).toInstant());
        Date created = Date.from(date.atZone(ZoneId.systemDefault()).toInstant());
        System.out.println("Diferença data: " + (out.getTime() - created.getTime()));
        revogado = (out.getTime() - created.getTime()) > 100000;
    }
}
