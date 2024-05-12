import java.io.Serializable;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

/**
 * Class that represents a certificate
 */
public class Certificate implements Serializable {
    private String username;
    private PublicKey publicRSAKey;
    private static int ID = 1;
    private String certificateID;
    private byte[] signature;
    private boolean revogado = false;
    private LocalDateTime date;

    /**
     * Constructor of the class
     * @param username client username
     * @param publicRSAKey client public RSA key
     * @param date date of the certificate
     */
    public Certificate(String username, PublicKey publicRSAKey, LocalDateTime date) {
        this.username = username;
        this.publicRSAKey = publicRSAKey;
        this.certificateID = "CERTIFICATE" + ID;
        this.date = date;
        ID++;
    }

    /**
     * Method that returns the username
     * @return username
     */
    public String getUsername() {
        return username;
    }

    /**
     * Metohd that returns the Public RSA Key
     * @return publicRSAKey
     */
    public PublicKey getPublicRSAKey() {
        return publicRSAKey;
    }

    /**
     * Method that returns the date
     * @return date
     */
    public LocalDateTime getDate(){
        return date;
    }

    /**
     * Method that returns whether the certificate is revoked or not
     * @return boolean
     */
    public boolean isRevogado() {
        return revogado;
    }

    /**
     * Method which checks if the certificate is revoked
     */
    public void checkRevogado() {
        LocalDateTime now = LocalDateTime.now();
        Date out = Date.from(now.atZone(ZoneId.systemDefault()).toInstant());
        Date created = Date.from(date.atZone(ZoneId.systemDefault()).toInstant());
        System.out.println("Diferença data: " + (out.getTime() - created.getTime()));
        revogado = (out.getTime() - created.getTime()) > 100000;
    }
}
