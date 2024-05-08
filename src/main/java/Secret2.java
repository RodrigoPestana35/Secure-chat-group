import java.io.Serializable;

public class Secret2 implements Serializable {
    private byte[] secret;
    private byte[] receiver;
    private byte[] sender;

    public Secret2(byte[] secret, byte[] receiver, byte[] sender) {
        this.secret = secret;
        this.receiver = receiver;
        this.sender = sender;

    }

    public byte[] getSecret() {
        return secret;
    }

    public byte[] getReceiver() {
        return receiver;
    }

    public byte[] getSender() {
        return sender;
    }
}
