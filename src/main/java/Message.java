import java.io.Serializable;

/**
 * This class represents a message object that is sent between the client and the server.
 */
public class Message implements Serializable {

    private final byte[] message;
    private final byte[] digest;
    private String receiver;
    private String sender;

    /**
     * Constructs a Message object by specifying the message bytes that will be sent between the client and the server.
     *
     * @param message the message that is sent to the server
     */
    public Message ( byte[] message, byte[] digest, String sender, String receiver ) {
        this.digest = digest;
        this.message = message;
        this.receiver = receiver;
        this.sender = sender;
    }

    public Message ( byte[] message, byte[] digest, String sender ) {
        this.digest = digest;
        this.message = message;
        this.sender = sender;
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