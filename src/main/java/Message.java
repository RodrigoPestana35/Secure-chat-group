import java.io.Serializable;

/**
 * This class represents a message object that is sent between the client and the server.
 */
public class Message implements Serializable {

    private final byte[] message;
    private byte[] digest;
    private byte[] receiver;
    private byte[] sender;
    private byte[] control; //0 - mensagem, 1 - troca de chaves, 2 - in outs

    /**
     * Constructs a Message object by specifying the message bytes that will be sent between the client and the server.
     *
     * @param message the message that is sent to the server
     */
    public Message ( byte[] message, byte[] digest, byte[] sender, byte[] receiver, byte[] control) {
        this.digest = digest;
        this.message = message;
        this.receiver = receiver;
        this.sender = sender;
        this.control = control;
    }

    public Message ( byte[] message, byte[] receiver, byte[] control ) {
        this.message = message;
        this.receiver = receiver;
        this.control = control;
    }

    public Message(byte[] message, byte[] control) {
        this.message = message;
        this.control = control;
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

    public byte[] getControl() {
        return control;
    }
}