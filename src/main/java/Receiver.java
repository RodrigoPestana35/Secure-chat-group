import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;

/**
 * This class represents a server that receives a message from the client. The server is implemented as a thread.
 */
public class Receiver implements Runnable {

    private final ServerSocket server;
    private final PublicKey publicRSAKey;
    private final PrivateKey privateRSAKey;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private Socket client;
    private HashMap<String, ObjectInputStream> usersIns;
    private HashMap<String, ObjectOutputStream> usersOuts;

    /**
     * Constructs a Receiver object by specifying the port number. The server will be then created on the specified
     * port. The Receiver will be accepting connections from all local addresses.
     *
     * @param port the port number
     *
     * @throws IOException if an I/O error occurs when opening the socket
     */
    public Receiver ( int port ) throws Exception {
        server = new ServerSocket ( port );
        KeyPair keyPair = Encryption.generateKeyPair();
        this.publicRSAKey = keyPair.getPublic();
        this.privateRSAKey = keyPair.getPrivate();
    }

    @Override
    public void run() {
        try {
            while (true) {
                final Socket client = server.accept();
                new Thread(() -> {
                    try {
                        ObjectInputStream in = new ObjectInputStream(client.getInputStream());
                        ObjectOutputStream out = new ObjectOutputStream(client.getOutputStream());
                        process(in);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }).start();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Processes the request from the client.
     *
     * @param in the input stream
     *
     * @throws Exception if an I/O error occurs when reading the message
     */
    private void process ( ObjectInputStream in ) throws Exception {
        Message messageObj = ( Message ) in.readObject ( );
        if(!usersIns.containsKey(messageObj.getSender()) && !usersOuts.containsKey(messageObj.getSender())){
            usersIns.put(messageObj.getSender(), in);
            usersOuts.put(messageObj.getSender(), out);
        }
        String receiverName = messageObj.getReceiver();
        ObjectOutputStream receiverOut = usersOuts.get(receiverName);
        receiverOut.writeObject(messageObj);
    }

    private BigInteger agreeOnSharedSecret(PublicKey senderPublicRSAKey) throws Exception {
        BigInteger privateDHKey = DiffieHellman.generatePrivateKey();
        BigInteger publicDHKey = DiffieHellman.calculatePublicKey(privateDHKey);

        byte[] senderPublicKeyEncrypted = (byte[]) (in.readObject());
        byte[] senderPublicKeyDecrypted = Encryption.decryptRSA(senderPublicKeyEncrypted, senderPublicRSAKey);

        byte[] publicKeyEncrypted = Encryption.encryptRSA(publicDHKey.toByteArray(),privateRSAKey);
        sendPublicKey(publicKeyEncrypted);

        return DiffieHellman.computeSecret(new BigInteger(senderPublicKeyDecrypted), privateDHKey);
    }

    private PublicKey rsaKeyDistribution() throws IOException, ClassNotFoundException {
        PublicKey publicKey = (PublicKey) in.readObject();
        out.writeObject(this.publicRSAKey);
        return publicKey;
    }

    private void sendPublicKey(byte[] publicKeyEncrypted) throws IOException {
        out.writeObject(publicKeyEncrypted);
    }


    /**
     * Closes the connection and the associated streams.
     *
     * @throws IOException if an I/O error occurs when closing the socket
     */
    private void closeConnection ( ) throws IOException {
        client.close ( );
        out.close ( );
        in.close ( );
    }

}