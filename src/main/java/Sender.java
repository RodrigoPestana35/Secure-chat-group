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
public class Sender implements Runnable {

    private static final String HOST = "0.0.0.0";
    private static int port = 8000;
    private final Socket client;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final PublicKey publicRSAKey;
    private final PrivateKey privateRSAKey;
    private final PublicKey receiverPublicRSAKey;

    /**
     * Constructs a Sender object by specifying the port to connect to. The socket must be created before the sender can
     * send a message.
     *
     * @throws Exception when an I/O error occurs when creating the socket
     */
    public Sender ( ) throws Exception {
        client = new Socket ( HOST , port );
        port++;
        out = new ObjectOutputStream ( client.getOutputStream ( ) );
        in = new ObjectInputStream ( client.getInputStream ( ) );

        KeyPair keyPair = Encryption.generateKeyPair();
        this.publicRSAKey = keyPair.getPublic();
        this.privateRSAKey = keyPair.getPrivate();

        this.receiverPublicRSAKey = rsaKeyDistribution();
    }

    private PublicKey rsaKeyDistribution() throws IOException, ClassNotFoundException {
        out.writeObject(this.publicRSAKey);
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
        BigInteger sharedSecret = agreeOnSharedSecretSend();
        // Creates the message object
        Message messageObj = new Message ( Encryption.encryptAES( message.getBytes ( ), sharedSecret.toByteArray() ), Encryption.encryptRSA(Integrity.generateDigest(message.getBytes()),privateRSAKey));
        // Sends the message
        out.writeObject ( messageObj );
        // Close connection
        closeConnection ( );
    }

    public void receiveMessage () throws Exception {
        PublicKey senderPublicRSAKey = rsaKeyDistribution();

        byte[] sharedSecret = agreeOnSharedSecretReceive(senderPublicRSAKey).toByteArray();

        // Reads the message object
        Message messageObj = ( Message ) in.readObject ( );
        byte[] decryptedMessage = Encryption.decryptAES( messageObj.getMessage ( ), sharedSecret );
        byte[] computedDigest = Integrity.generateDigest(decryptedMessage);
        byte[] receivedDigest = Encryption.decryptRSA(messageObj.getDigest(), senderPublicRSAKey);
        if(Integrity.verifyDigest(computedDigest, receivedDigest)){
            System.out.println(new String(decryptedMessage));
        }
    }

    private BigInteger agreeOnSharedSecretReceive(PublicKey senderPublicRSAKey) throws Exception {
        BigInteger privateDHKey = DiffieHellman.generatePrivateKey();
        BigInteger publicDHKey = DiffieHellman.calculatePublicKey(privateDHKey);

        byte[] senderPublicKeyEncrypted = (byte[]) (in.readObject());
        byte[] senderPublicKeyDecrypted = Encryption.decryptRSA(senderPublicKeyEncrypted, senderPublicRSAKey);

        byte[] publicKeyEncrypted = Encryption.encryptRSA(publicDHKey.toByteArray(),privateRSAKey);
        sendPublicKey(publicKeyEncrypted);

        return DiffieHellman.computeSecret(new BigInteger(senderPublicKeyDecrypted), privateDHKey);
    }

    private BigInteger agreeOnSharedSecretSend() throws Exception {
        BigInteger privateDHKey = DiffieHellman.generatePrivateKey();
        BigInteger publicDHKey = DiffieHellman.calculatePublicKey(privateDHKey);

        byte[] publicKeyEncrypted = Encryption.encryptRSA(publicDHKey.toByteArray(), privateRSAKey);
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

    @Override
    public void run() {
        try {
            sendMessage("Hello, World!");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
