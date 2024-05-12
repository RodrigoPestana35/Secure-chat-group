import java.io.Serializable;

/**
 * This class represents a message object that is sent between the client and the server.
 */
public class Message implements Serializable {

    private final byte[] message;
    private byte[] digest;
    private byte[] receiver;
    private byte[] sender;

    /**
     * Constructs a Message object by specifying the message bytes that will be sent between the client and the server.
     *
     * @param message the message that is sent to the server
     * @param digest the digest of the message
     * @param sender the sender of the message
     * @param receiver the receiver of the message
     */
    public Message ( byte[] message, byte[] digest, byte[] sender, byte[] receiver ) {
        this.digest = digest;
        this.message = message;
        this.receiver = receiver;
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

    /**
     * Gets the digest bytes.
     *
     * @return the digest bytes
     */
    public byte[] getDigest() {
        return digest;
    }

    /**
     * Gets the receiver bytes.
     *
     * @return the receiver bytes
     */
    public byte[] getReceiver() {
        return receiver;
    }

    /**
     * Gets the sender bytes.
     *
     * @return the sender bytes
     */
    public byte[] getSender() {
        return sender;
    }

}