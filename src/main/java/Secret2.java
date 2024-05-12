import java.io.Serializable;

/**
 * This class represents a secret object that is sent between the client and the server.
 */
public class Secret2 implements Serializable {
    private byte[] secret;
    private byte[] receiver;
    private byte[] sender;

    /**
     * Constructs a Secret object by specifying the secret bytes that will be sent between the client and the server.
     *
     * @param secret the secret that is sent to the server
     */
    public Secret2(byte[] secret, byte[] receiver, byte[] sender) {
        this.secret = secret;
        this.receiver = receiver;
        this.sender = sender;

    }

    /**
     * Gets the secret bytes.
     *
     * @return the secret bytes
     */
    public byte[] getSecret() {
        return secret;
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
