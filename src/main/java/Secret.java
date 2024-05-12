import java.io.Serializable;

/**
 * This class represents a secret object that is sent between the client and the server.
 */
public class Secret implements Serializable {
    private final byte[] secret;
    private final byte[] receiver;
    private final byte[] sender;

    /**
     * Constructs a Secret object by specifying the secret bytes that will be sent between the client and the server.
     *
     * @param secret the secret that is sent to the server
     * @param receiver the receiver of the secret
     * @param sender the sender of the secret
     */
    public Secret(byte[] secret, byte[] receiver, byte[] sender) {
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
