import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * This class represents the sender of the message. It sends the message to the receiver by means of a socket. The use
 * of Object streams enables the sender to send any kind of object.
 */
public class Sender {

    private static final String HOST = "0.0.0.0";
    private final Socket client;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final PublicKey publicRASKey;
    private final PrivateKey privateRASKey;
    private final PublicKey receiverPublicRSAKey;

    /**
     * Constructs a Sender object by specifying the port to connect to. The socket must be created before the sender can
     * send a message.
     *
     * @param port the port to connect to
     *
     * @throws Exception when an I/O error occurs when creating the socket
     */
    public Sender ( int port ) throws Exception {
        client = new Socket ( HOST , port );
        out = new ObjectOutputStream ( client.getOutputStream ( ) );
        in = new ObjectInputStream ( client.getInputStream ( ) );

        KeyPair keyPair = Encryption.generateKeyPair();
        this.publicRASKey = keyPair.getPublic();
        this.privateRASKey = keyPair.getPrivate();

        this.receiverPublicRSAKey = rsaKeyDistribution();
    }

    private PublicKey rsaKeyDistribution() throws IOException, ClassNotFoundException {
        out.writeObject(this.publicRASKey);
        return (PublicKey) in.readObject();
    }

    /**
     * Sends a message to the receiver using the OutputStream of the socket. The message is sent as an object of the
     * {@link Message} class.
     *
     * @param message the message to send
     *
     * @throws Exception when an I/O error occurs when sending the message
     */
    public void sendMessage ( String message ) throws Exception {
        BigInteger sharedSecret = agreeOnSharedSecret();
        // Creates the message object
        Message messageObj = new Message ( Encryption.encryptAES( message.getBytes ( ), sharedSecret.toByteArray() ), Encryption.encryptRSA(Integrity.generateDigest(message.getBytes()),privateRASKey));
        // Sends the message
        out.writeObject ( messageObj );
        // Close connection
        closeConnection ( );
    }

    private BigInteger agreeOnSharedSecret() throws Exception {
        BigInteger privateDHKey = DiffieHellman.generatePrivateKey();
        BigInteger publicDHKey = DiffieHellman.calculatePublicKey(privateDHKey);

        byte[] publicKeyEncrypted = Encryption.encryptRSA(publicDHKey.toByteArray(), privateRASKey);
        sendPublicKey(publicKeyEncrypted);

        byte[] receiverPublicKeyEncrypted = (byte[])(in.readObject());
        byte[] receiverPublicKeyDecrypted = Encryption.decryptRSA(receiverPublicKeyEncrypted, receiverPublicRSAKey);

        return DiffieHellman.computeSecret(new BigInteger(receiverPublicKeyDecrypted),privateDHKey);
    }

    private void sendPublicKey(byte[] publicKeyEncrypted) throws IOException {
        out.writeObject(publicKeyEncrypted);
    }

    /**
     * Closes the connection by closing the socket and the streams.
     *
     * @throws IOException when an I/O error occurs when closing the connection
     */
    private void closeConnection ( ) throws IOException {
        client.close ( );
        out.close ( );
        in.close ( );
    }

}
