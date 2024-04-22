import java.io.Serializable;

/**
 * This class represents a message object that is sent between the client and the server.
 */
public class Message implements Serializable {

    private final byte[] message;
    private final byte[] digest;

    /**
     * Constructs a Message object by specifying the message bytes that will be sent between the client and the server.
     *
     * @param message the message that is sent to the server
     */
    public Message ( byte[] message, byte[] digest ) {
        this.digest = digest;
        this.message = message;
    }

    /**
     * Gets the message string.
     *
     * @return the message string
     */
    public byte[] getMessage ( ) {
        return message;
    }


    public byte[] getDigest() {
        return digest;
    }
}