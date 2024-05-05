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
     */
    public Message ( byte[] message, byte[] digest, byte[] sender, byte[] receiver ) {
        this.digest = digest;
        this.message = message;
        this.receiver = receiver;
        this.sender = sender;
    }

    public Message ( byte[] message, byte[] receiver, byte[] sender ) {
        this.message = message;
        this.receiver = receiver;
        this.sender = sender;
    }

    public Message(byte[] message, byte[] receiver) {
        this.message = message;
        this.receiver = receiver;
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

    public byte[] getReceiver() {
        return receiver;
    }

    public byte[] getSender() {
        return sender;
    }

}